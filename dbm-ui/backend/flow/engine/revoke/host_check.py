# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-DB管理系统(BlueKing-BK-DBM) available.
Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

主机退回资源池判定公共类。

模块职责：
  - 提供 F1~F4 单机判据采集方法（返回 FactCheckOutcome / FactState 三态）：
    1) check_f1_ownership       —— F1 所有权（MachineEvent 最近事件 ticket 归属）
    2) check_f2_traffic         —— F2 客户端流量红线（DNS + CLB 聚合）
    3) check_f3_dbm_residue     —— F3 DBM 残留（Machine/ProxyInstance/StorageInstance/Tuple 任一命中）
    4) check_f4_process         —— F4 进程存活（解析主机进程检查脚本的 ctx JSON）
  - 提供两个可复用的外部真相探针（被 F2 子判据内部消费；亦可被联调脚本单独调用）：
    * check_clb_mapping         —— IP 在 CLB 侧是否仍有后端注册（外部真相）
    * check_dns_mapping         —— IP 在 DNS 服务侧是否仍有解析记录（外部真相）
  - 提供进程检查脚本输出解析器：parse_process_check_result

设计要点：
  - **只读、无副作用**：所有方法不写 DB、不发起变更类 RPC、不写 FlowOutputHandler
  - **外部真相为准**：check_clb_mapping / check_dns_mapping 完全不查 DBM 元数据，
    只以 (ip, region) / (ip, bk_cloud_id) 为主键去外部服务查真相；
    避免"元数据已清 + 外部残留"这一"最危险的中间态"被漏检
  - **不预留进程检查钩子**：进程存活性由 dbactor 侧独立实现，本类保持职责单一
  - **异常不上抛**：外部服务调用异常统一封装为 reason_code="check_error"，
    保证 revoke 流程主链路不被此类检查中断
  - **结构化结果三段职责**：
      * reason_code —— 面向机器（枚举分支）
      * reason      —— 面向人（可读文本），必填非空
      * evidence    —— 面向排查（结构化证据）

边界：
  - 本模块仅做"判定"，不做"清理"；具体清理/退回动作由上层 revoke flow 编排
  - 4 个方法结果正交、互不掩盖，元数据缺失不影响外部服务判定的独立报告
"""
import logging
import traceback
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from backend.components import CCApi, DRSApi
from backend.components.db_name_service.client import NameServiceApi
from backend.components.dns.client import DnsApi
from backend.db_dirty.models import MachineEvent
from backend.db_meta.enums import ClusterType, ClusterTypeMachineTypeDefine
from backend.db_meta.models import Machine, ProxyInstance, StorageInstance, StorageInstanceTuple
from backend.db_meta.models.cluster_monitor import ClusterMonitorTopo
from backend.db_services.cmdb.biz import get_or_create_resource_module
from backend.flow.engine.revoke.exception import RevokeFlowBaseException
from backend.flow.engine.revoke.models import (
    F2_SUB_KEY_CLB,
    F2_SUB_KEY_DNS,
    F3_EV_KEY_MACHINE,
    F3_EV_KEY_PROXIES,
    F3_EV_KEY_STORAGES,
    F3_EV_KEY_TUPLES,
    FactCheckOutcome,
    FactState,
    RevokeUnit,
)
from backend.ticket.models import Ticket

logger = logging.getLogger("flow")


class HostCheckReasonCode:
    """判定结果 reason_code 枚举常量集合。

    职责：集中定义 4 个判定方法可能返回的所有 reason_code 字符串，
      供上层做分支处理（if/switch）时使用；面向机器、非展示文本。
    """

    #: 判定通过
    OK: str = "ok"

    #: 需求 3：未提供 region，无法判定 CLB 注册状态
    NO_REGION_INPUT: str = "no_region_input"
    #: 需求 3：IP 已注册在 CLB 上
    IP_REGISTERED_IN_CLB: str = "ip_registered_in_clb"
    #: 需求 3：IP 未注册在 CLB 上
    IP_NOT_REGISTERED_IN_CLB: str = "ip_not_registered_in_clb"

    #: 需求 4：IP 仍有 DNS 记录
    IP_HAS_DNS_RECORD: str = "ip_has_dns_record"
    #: 需求 4：IP 无 DNS 记录
    IP_NO_DNS_RECORD: str = "ip_no_dns_record"

    #: 需求 7（MySQL 主机进程存活检查）：主机上仍有 MySQL 家族进程 LISTEN
    #: （方案已收敛为"主机维度"扫描：只要命中白名单中任一 comm 即视为存活，
    #: 不再区分 process_missing / port_hijacked / partial_alive）
    MYSQL_STILL_ALIVE: str = "mysql_still_alive"

    #: 通用兜底：外部服务异常 / DB 查询异常
    CHECK_ERROR: str = "check_error"


@dataclass
class HostCheckResult:
    """单次判定的结构化结果。

    字段职责三分：
      * ``reason_code`` 面向机器（枚举分支）
      * ``reason``      面向人（展示文本，必填非空）
      * ``evidence``    面向排查（结构化证据）

    边界：
      - ``reason`` 强制非空字符串，若为空将在 ``__post_init__`` 抛异常
      - ``evidence`` 允许为空 dict，但不允许为 None
    """

    #: 判定是否通过
    passed: bool
    #: 结果分类枚举字符串，取值见 :class:`HostCheckReasonCode`
    reason_code: str
    #: 人类可读的原因说明，无论 passed 真假都必填非空
    reason: str
    #: 判定依据的关键证据字段，用于详细溯源
    evidence: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """校验 ``reason`` 非空、``evidence`` 非 None。

        :return: None
        边界：
          - ``reason`` 为 None / 空串 / 纯空白 -> raise RevokeFlowBaseException
          - ``evidence`` 为 None -> 自动置为 {}
        """
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise RevokeFlowBaseException(
                "HostCheckResult.reason must be non-empty string, got: {!r}".format(self.reason)
            )
        if self.evidence is None:
            self.evidence = {}


#: check_dns_mapping 中 evidence.records 仅保留的白名单字段
_DNS_RECORD_KEEP_FIELDS: Tuple[str, ...] = ("domain_name", "port", "status", "last_change_time")

#: 日志脱敏时需要剔除的敏感字段名（进程内小写匹配）
_SENSITIVE_FIELD_NAMES: frozenset = frozenset(
    {"clb_token", "servicetoken", "aliastoken", "token", "secret", "password"}
)


class HostRevokeChecker:
    """主机退回资源池判定公共类。

    职责：
      - 收敛 4 个独立、只读、无副作用的判定方法，供多个 revoke flow 复用
      - 每个判定方法各自返回 :class:`HostCheckResult`，结果正交互不掩盖
      - 外部服务调用异常统一封装为 CHECK_ERROR，不向上抛出中断流程

    使用方式：
        checker = HostRevokeChecker(
            root_id="root-xxx",
            ticket=ticket_obj,
            bk_biz_id=100,
            bk_cloud_id=0,
            ip="1.2.3.4",
            bk_host_id=123456,
        )
        # F 判据（3 态，供 revoke 决策矩阵消费）
        f1 = checker.check_f1_ownership()
        f2 = checker.check_f2_traffic(unit=unit, alive_proxies=..., clb_regions=[...])
        f3 = checker.check_f3_dbm_residue(unit=unit)
        f4 = HostRevokeChecker.check_f4_process(process_check_ctx_json=..., ip="1.2.3.4")
        # 外部真相探针（可单独调用，被 F2 子判据内部复用）
        r_clb = checker.check_clb_mapping(regions=["南京"])
        r_dns = checker.check_dns_mapping()

    线程安全：**非线程安全**（进程内可变状态），单个 revoke flow 内串行使用即可；
      如需并发，请为每个线程各起一个实例。

    边界：
      - 构造入参任一为空或类型不合法 -> 抛 :class:`RevokeFlowBaseException`
      - 判定方法内部任何 DB / API 异常均被捕获封装，不向上抛出
    """

    def __init__(
        self,
        root_id: str,
        ticket: Ticket,
        bk_biz_id: int,
        bk_cloud_id: int,
        ip: str,
        bk_host_id: int,
    ) -> None:
        """初始化判定器：只做赋值 + 参数校验，不做 IO/RPC/DB 调用。

        :param root_id: flow root_id，用于日志追踪
        :param ticket: 当前单据对象，需带有 ``id`` 属性
        :param bk_biz_id: 业务 id，> 0
        :param bk_cloud_id: 云区域 id，>= 0
        :param ip: 主机 IP，非空字符串
        :param bk_host_id: 主机 id，> 0
        :return: None
        边界：
          - 任一参数为空、类型不合法 -> raise RevokeFlowBaseException
        """
        if not isinstance(root_id, str) or not root_id.strip():
            raise RevokeFlowBaseException("root_id must be non-empty string")
        if ticket is None or not hasattr(ticket, "id"):
            raise RevokeFlowBaseException("ticket must be a Ticket instance with `id` attribute")
        if not isinstance(bk_biz_id, int) or bk_biz_id <= 0:
            raise RevokeFlowBaseException("bk_biz_id must be positive int")
        if not isinstance(bk_cloud_id, int) or bk_cloud_id < 0:
            raise RevokeFlowBaseException("bk_cloud_id must be non-negative int")
        if not isinstance(ip, str) or not ip.strip():
            raise RevokeFlowBaseException("ip must be non-empty string")
        if not isinstance(bk_host_id, int) or bk_host_id <= 0:
            raise RevokeFlowBaseException("bk_host_id must be positive int")

        self.root_id: str = root_id
        self.ticket: Ticket = ticket
        self.bk_biz_id: int = bk_biz_id
        self.bk_cloud_id: int = bk_cloud_id
        self.ip: str = ip
        self.bk_host_id: int = bk_host_id

    # ---------------- 私有工具 ----------------

    def _sanitize_evidence(self, evidence: Any) -> Any:
        """递归剔除敏感字段，用于日志与最终返回。

        :param evidence: 任意结构（dict / list / 标量）
        :return: 已剔除敏感字段的同结构对象
        边界：
          - 匹配以 :data:`_SENSITIVE_FIELD_NAMES` 为准（大小写不敏感）
          - 非 dict/list 直接返回原值
        """
        if isinstance(evidence, dict):
            cleaned: Dict[str, Any] = {}
            for k, v in evidence.items():
                if isinstance(k, str) and k.lower() in _SENSITIVE_FIELD_NAMES:
                    continue
                cleaned[k] = self._sanitize_evidence(v)
            return cleaned
        if isinstance(evidence, list):
            return [self._sanitize_evidence(item) for item in evidence]
        return evidence

    def _log_result(self, method: str, result: HostCheckResult) -> None:
        """按需求 7 的格式打印一行 INFO 汇总日志（含 reason）。

        :param method: 判定方法名，用于日志检索
        :param result: 判定结果对象
        :return: None
        边界：
          - passed=False 且 reason_code=CHECK_ERROR -> WARNING 级别
          - 其他情况 -> INFO 级别
        """
        line = (
            "[HostRevokeChecker][{root_id}][{ip}][{method}] "
            'passed={passed} reason_code={reason_code} reason="{reason}" evidence={evidence}'
        ).format(
            root_id=self.root_id,
            ip=self.ip,
            method=method,
            passed=result.passed,
            reason_code=result.reason_code,
            reason=result.reason,
            evidence=result.evidence,
        )
        if not result.passed and result.reason_code == HostCheckReasonCode.CHECK_ERROR:
            logger.warning(line)
        else:
            logger.info(line)

    def _build_result(
        self,
        method: str,
        passed: bool,
        reason_code: str,
        reason: str,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> HostCheckResult:
        """统一构造 :class:`HostCheckResult` 并触发日志。

        :param method: 判定方法名
        :param passed: 判定是否通过
        :param reason_code: 见 :class:`HostCheckReasonCode`
        :param reason: 人类可读原因（必填非空）
        :param evidence: 结构化证据；默认 {}
        :return: 已脱敏的 HostCheckResult
        边界：
          - evidence 内的敏感字段（如 clb_token）会被剔除
        """
        evidence = evidence or {}
        result = HostCheckResult(
            passed=passed,
            reason_code=reason_code,
            reason=reason,
            evidence=self._sanitize_evidence(evidence),
        )
        self._log_result(method=method, result=result)
        return result

    # ---------------- 需求 3：CLB 映射判定 ----------------

    def check_clb_mapping(self, regions: List[str]) -> HostCheckResult:
        """判定 IP 是否已注册在 CLB 后端上（完全不查 DBM 元数据）。

        怎么做：
          1) regions 全空 -> NO_REGION_INPUT（不使用 True 兜底）
          2) 遍历每个有效 region，调 NameServiceApi.clb_check_clb_register_target_by_ip
          3) 任一 region 的 clbinfos 存在 registerclb==True 且 ip 匹配 -> 短路 IP_REGISTERED_IN_CLB
          4) 单个 region 抛异常时捕获、记入 failed_regions，继续遍历后续 region
          5) 遍历结束无命中但存在 failed_regions -> CHECK_ERROR（保守）
          6) 否则 -> IP_NOT_REGISTERED_IN_CLB

        :param regions: 需要检查的 region 列表；由调用方决定 region 来源
        :return: :class:`HostCheckResult`
        边界：
          - regions 内空字符串会被过滤；若全部为空视为 NO_REGION_INPUT
          - 单个 region 异常不中断整体遍历
        """
        method = "check_clb_mapping"

        # 步骤 1：region 输入合法性
        if not regions:
            return self._build_result(
                method=method,
                passed=False,
                reason_code=HostCheckReasonCode.NO_REGION_INPUT,
                reason="未提供 region，无法判定 CLB 注册状态",
                evidence={"ip": self.ip, "regions": regions},
            )
        valid_regions: List[str] = [r for r in regions if isinstance(r, str) and r.strip()]
        if not valid_regions:
            return self._build_result(
                method=method,
                passed=False,
                reason_code=HostCheckReasonCode.NO_REGION_INPUT,
                reason="未提供 region，无法判定 CLB 注册状态",
                evidence={"ip": self.ip, "regions": regions},
            )

        all_responses: Dict[str, Any] = {}
        failed_regions: Dict[str, str] = {}
        matched_clbid: Optional[str] = None
        matched_region: Optional[str] = None

        # 步骤 2：遍历 region
        for region in valid_regions:
            try:
                resp = NameServiceApi.clb_check_clb_register_target_by_ip({"region": region, "ips": [self.ip]})
            except Exception as err:
                failed_regions[region] = str(err)
                logger.warning(
                    "[HostRevokeChecker][{}][{}][check_clb_mapping] region={} api error: {}".format(
                        self.root_id, self.ip, region, err
                    )
                )
                continue

            # 步骤 3：解析 clbinfos
            clbinfos: List[Dict[str, Any]] = []
            if isinstance(resp, dict):
                # 注：接口注释显示返回结构 data.clbinfos；但生产代码曾出现 resp["clbid"] 直读的用法，
                # 这里做兼容：优先取 clbinfos，缺失则视为无注册（配合 registerclb 严格判定）
                if isinstance(resp.get("clbinfos"), list):
                    clbinfos = resp["clbinfos"]
                elif isinstance(resp.get("data"), dict) and isinstance(resp["data"].get("clbinfos"), list):
                    clbinfos = resp["data"]["clbinfos"]

            for info in clbinfos:
                if not isinstance(info, dict):
                    continue
                if info.get("registerclb") is True and info.get("ip") == self.ip:
                    matched_clbid = info.get("clbid")
                    matched_region = region
                    break

            if matched_clbid is not None:
                break

        # 步骤 3 短路命中
        if matched_clbid is not None:
            return self._build_result(
                method=method,
                passed=False,
                reason_code=HostCheckReasonCode.IP_REGISTERED_IN_CLB,
                reason="该机器 IP 已注册在 CLB {} 上（region={}），需先解除绑定".format(matched_clbid, matched_region),
                evidence={
                    "ip": self.ip,
                    "matched_region": matched_region,
                    "matched_clbid": matched_clbid,
                    "all_responses": all_responses,
                },
            )

        # 步骤 5：无命中但存在 failed_regions
        if failed_regions:
            return self._build_result(
                method=method,
                passed=False,
                reason_code=HostCheckReasonCode.CHECK_ERROR,
                reason="部分 region 查询失败，从保守出发视为不干净（failed_regions={}）".format(list(failed_regions.keys())),
                evidence={
                    "ip": self.ip,
                    "failed_regions": list(failed_regions.keys()),
                    "errors": failed_regions,
                    "all_responses": all_responses,
                },
            )

        # 步骤 6：全部干净
        return self._build_result(
            method=method,
            passed=True,
            reason_code=HostCheckReasonCode.IP_NOT_REGISTERED_IN_CLB,
            reason="IP 在 checked_regions={} 中均未注册到 CLB".format(valid_regions),
            evidence={
                "ip": self.ip,
                "checked_regions": valid_regions,
                "all_responses": all_responses,
            },
        )

    # ---------------- 需求 4：DNS 映射判定 ----------------

    def check_dns_mapping(self) -> HostCheckResult:
        """判定 IP 在 DNS 服务侧是否仍有域名解析（完全不查 DBM 元数据）。

        怎么做：
          1) 调 DnsApi.get_domain({"ip", "bk_cloud_id"}) 反查
          2) 返回值非 dict / 缺 detail 键 -> CHECK_ERROR
          3) detail 为空 -> IP_NO_DNS_RECORD
          4) detail 非空 -> IP_HAS_DNS_RECORD，records 仅保留定位字段

        :return: :class:`HostCheckResult`
        边界：
          - DnsApi 异常 -> CHECK_ERROR（保守策略，视为不干净）
          - passed=False 分支会在日志中打印完整 domain_name 列表
        """
        method = "check_dns_mapping"

        # 步骤 1：调用 DNS 接口
        try:
            resp = DnsApi.get_domain({"ip": self.ip, "bk_cloud_id": self.bk_cloud_id})
        except Exception as err:
            return self._build_result(
                method=method,
                passed=False,
                reason_code=HostCheckReasonCode.CHECK_ERROR,
                reason="DNS 接口调用失败：{}".format(err),
                evidence={
                    "ip": self.ip,
                    "bk_cloud_id": self.bk_cloud_id,
                    "error": str(err),
                    "trace": traceback.format_exc(limit=3),
                },
            )

        # 步骤 2：返回结构合法性
        if not isinstance(resp, dict) or "detail" not in resp:
            return self._build_result(
                method=method,
                passed=False,
                reason_code=HostCheckReasonCode.CHECK_ERROR,
                reason="DNS 接口返回结构异常（缺少 detail 键或非 dict）",
                evidence={
                    "ip": self.ip,
                    "bk_cloud_id": self.bk_cloud_id,
                    "raw_response": resp,
                },
            )

        detail = resp.get("detail") or []
        if not isinstance(detail, list):
            return self._build_result(
                method=method,
                passed=False,
                reason_code=HostCheckReasonCode.CHECK_ERROR,
                reason="DNS 接口返回 detail 字段非 list",
                evidence={
                    "ip": self.ip,
                    "bk_cloud_id": self.bk_cloud_id,
                    "raw_response": resp,
                },
            )

        # 步骤 3：detail 为空 -> 干净
        if not detail:
            return self._build_result(
                method=method,
                passed=True,
                reason_code=HostCheckReasonCode.IP_NO_DNS_RECORD,
                reason="DNS 服务无该 IP 的解析记录",
                evidence={
                    "ip": self.ip,
                    "bk_cloud_id": self.bk_cloud_id,
                    "rowsNum": 0,
                },
            )

        # 步骤 4：detail 非空 -> 有残留
        records: List[Dict[str, Any]] = []
        all_domain_names: List[str] = []
        for item in detail:
            if not isinstance(item, dict):
                continue
            rec = {k: item.get(k) for k in _DNS_RECORD_KEEP_FIELDS if k in item}
            records.append(rec)
            dn = item.get("domain_name")
            if dn:
                all_domain_names.append(dn)

        rows_num: int = resp.get("rowsNum") if isinstance(resp.get("rowsNum"), int) else len(records)
        sample_domain: str = all_domain_names[0] if all_domain_names else ""

        # 需求 4.8：passed=False 时日志额外打印完整 domain_name 列表
        logger.info(
            "[HostRevokeChecker][{}][{}][check_dns_mapping] matched domains={}".format(
                self.root_id, self.ip, all_domain_names
            )
        )

        return self._build_result(
            method=method,
            passed=False,
            reason_code=HostCheckReasonCode.IP_HAS_DNS_RECORD,
            reason="该机器 IP 仍有 {} 条 DNS 记录（例：{}），需先清理 DNS".format(rows_num, sample_domain),
            evidence={
                "ip": self.ip,
                "bk_cloud_id": self.bk_cloud_id,
                "rowsNum": rows_num,
                "records": records,
            },
        )

    # ---------------- F1~F4 单机判据采集 ----------------

    def check_f1_ownership(self, unit: RevokeUnit) -> FactCheckOutcome:
        """F1 · 所有权判据：机器归属本单据 且 处于本 (bk_biz_id + db_type) 管控范围。

        判定分两段串行（任一段判 NO 即短路返回，段 1 优先）：

        段 1 · 属于本单据管控：
          - 从 ``self.ticket.details["parent_ticket"]`` 取 apply 原单据 id
            （RECYCLE_APPLY_HOST 的 details 由 :meth:`Ticket.create_recycle_ticket` 写入，
             parent_ticket = 真正申请这批机器的原 apply 单据 id）
          - 缺失 / 非法 → 直接抛 :class:`RevokeFlowBaseException` 短路给上层（契约违反）
          - 查 ``MachineEvent`` 表最近一次事件，``ticket_id == parent_ticket_id`` → 段 1 通过
          - 无事件 或 ticket 不匹配 → **F1=NO**（机器与本单无关联痕迹）

        段 2 · 属于本 (bk_biz_id + db_type) 管控范围（双通道任一命中即通过）：
          - 调 CCApi 查该 bk_host_id 的 bk_module_id 列表
          - 通道 A · 资源池模块：命中 :func:`get_or_create_resource_module` 的模块 id
              → 机器"还没交付"或"已归还到资源池"，视为本单管控内
          - 通道 B · DBM 集群模块：命中 :class:`ClusterMonitorTopo` 表中
              ``bk_biz_id == self.bk_biz_id`` 且
              ``machine_type ∈ ClusterTypeMachineTypeDefine[unit.cluster_type]`` 的模块
              → 机器"已交付到本 db_type 的集群模块下"，视为本单管控内
          - 通道 A / 通道 B 均不命中 → **F1=NO**（视为非法移动到其他业务 / 其他 db_type）

        :param unit: 判定所属 RevokeUnit；用 ``unit.cluster_type`` 反查 db_type
            对应的 machine_type 白名单，用于收紧 ClusterMonitorTopo 查询
        :return: :class:`FactCheckOutcome`
        :raises RevokeFlowBaseException: parent_ticket 缺失或非法（契约违反 · 短路上抛）
        边界：
          - MachineEvent DB 查询异常 → state=UNKNOWN
          - CC 接口异常 → state=UNKNOWN（外部服务保守降级，避免误清理）
          - 资源池模块获取失败 → state=UNKNOWN
          - ClusterMonitorTopo DB 查询异常 → state=UNKNOWN
          - CC 查询不到该主机（cc_records=[]） → state=NO（视作已从 CC 撤销）
          - unit.cluster_type 非法 → state=UNKNOWN
        """
        if not isinstance(unit, RevokeUnit):
            return FactCheckOutcome(
                state=FactState.UNKNOWN,
                error="unit is not RevokeUnit",
                reason="F1 输入 unit 类型非法",
            )

        # ==================== 段 1：属于本单据管控 ====================
        parent_ticket_id: int = self._extract_parent_ticket_id()

        try:
            last_event = MachineEvent.objects.filter(bk_host_id=self.bk_host_id).order_by("-id").first()
        except Exception as err:
            logger.warning(
                "[HostRevokeChecker][{}][{}][check_f1_ownership] MachineEvent query error: {}".format(
                    self.root_id, self.ip, err
                )
            )
            return FactCheckOutcome(
                state=FactState.UNKNOWN,
                evidence={"bk_host_id": self.bk_host_id, "parent_ticket_id": parent_ticket_id, "error": str(err)},
                error=str(err),
                reason="F1 MachineEvent 查询异常：{}".format(err),
            )

        if last_event is None:
            return FactCheckOutcome(
                state=FactState.NO,
                evidence={
                    "bk_host_id": self.bk_host_id,
                    "parent_ticket_id": parent_ticket_id,
                    "last_event": None,
                },
                reason="F1=NO：机器无任何 MachineEvent 记录，与本单据无关联痕迹",
            )

        last_event_ticket_id: Optional[int] = last_event.ticket_id
        if last_event_ticket_id != parent_ticket_id:
            return FactCheckOutcome(
                state=FactState.NO,
                evidence={
                    "bk_host_id": self.bk_host_id,
                    "parent_ticket_id": parent_ticket_id,
                    "last_event_id": last_event.id,
                    "last_event_type": last_event.event,
                    "last_event_ticket_id": last_event_ticket_id,
                },
                reason="F1=NO：机器最近一次事件关联单据 {} 与本单 apply parent_ticket {} 不一致".format(
                    last_event_ticket_id, parent_ticket_id
                ),
            )

        # ==================== 段 2：属于本 (bk_biz_id + db_type) 管控 ====================
        # 段 1 通过后段 2 的 evidence 基线，避免每个 return 分支都重写一遍
        f1_evidence_base: Dict[str, Any] = {
            "bk_host_id": self.bk_host_id,
            "parent_ticket_id": parent_ticket_id,
            "last_event_id": last_event.id,
            "last_event_type": last_event.event,
            "last_event_ticket_id": last_event_ticket_id,
        }

        # 2.1 反查本单 cluster_type 对应的 machine_type 白名单（等价"限定 db_type"）
        try:
            cluster_type_enum = ClusterType(unit.cluster_type)
            allowed_machine_types: List[str] = [mt.value for mt in ClusterTypeMachineTypeDefine[cluster_type_enum]]
        except (ValueError, KeyError) as err:
            logger.warning(
                "[HostRevokeChecker][{}][{}][check_f1_ownership] invalid cluster_type={!r}: {}".format(
                    self.root_id, self.ip, unit.cluster_type, err
                )
            )
            return FactCheckOutcome(
                state=FactState.UNKNOWN,
                evidence={**f1_evidence_base, "cluster_type": unit.cluster_type, "error": str(err)},
                error=str(err),
                reason="F1 unit.cluster_type={!r} 非法或未在 ClusterTypeMachineTypeDefine 中定义".format(unit.cluster_type),
            )

        # 2.2 CC 查询该主机的 bk_module_id 列表
        try:
            cc_records: List[Dict[str, Any]] = CCApi.find_host_biz_relations({"bk_host_id": [self.bk_host_id]}) or []
        except Exception as err:
            logger.warning(
                "[HostRevokeChecker][{}][{}][check_f1_ownership] CC find_host_biz_relations error: {}".format(
                    self.root_id, self.ip, err
                )
            )
            return FactCheckOutcome(
                state=FactState.UNKNOWN,
                evidence={**f1_evidence_base, "error": str(err), "trace": traceback.format_exc(limit=3)},
                error=str(err),
                reason="F1 CC 接口调用异常：{}".format(err),
            )

        if not cc_records:
            return FactCheckOutcome(
                state=FactState.NO,
                evidence={**f1_evidence_base, "cc_bk_module_ids": []},
                reason="F1=NO：CC 查询不到该主机（bk_host_id={}）".format(self.bk_host_id),
            )

        actual_bk_module_ids: List[int] = sorted(
            {int(rec.get("bk_module_id") or 0) for rec in cc_records if rec.get("bk_module_id")}
        )
        if not actual_bk_module_ids:
            return FactCheckOutcome(
                state=FactState.NO,
                evidence={**f1_evidence_base, "cc_records_count": len(cc_records), "cc_bk_module_ids": []},
                reason="F1=NO：CC 返回的 host_biz_relations 中未包含有效 bk_module_id",
            )

        # 2.3 通道 A · 是否属于资源池模块
        try:
            resource_bk_module_id: int = int(get_or_create_resource_module())
        except Exception as err:
            logger.warning(
                "[HostRevokeChecker][{}][{}][check_f1_ownership] get_or_create_resource_module error: {}".format(
                    self.root_id, self.ip, err
                )
            )
            return FactCheckOutcome(
                state=FactState.UNKNOWN,
                evidence={**f1_evidence_base, "cc_bk_module_ids": actual_bk_module_ids, "error": str(err)},
                error=str(err),
                reason="F1 获取资源池模块 id 失败：{}".format(err),
            )

        # 2.4 通道 B · 是否属于本 (bk_biz_id + db_type) 的 ClusterMonitorTopo 模块
        # ClusterMonitorTopo 无 db_type 字段，用 machine_type__in 白名单等价过滤
        try:
            dbm_matched_module_ids: List[int] = sorted(
                set(
                    ClusterMonitorTopo.objects.filter(
                        bk_biz_id=self.bk_biz_id,
                        machine_type__in=allowed_machine_types,
                        bk_module_id__in=actual_bk_module_ids,
                    )
                    .values_list("bk_module_id", flat=True)
                    .distinct()
                )
            )
        except Exception as err:
            logger.warning(
                "[HostRevokeChecker][{}][{}][check_f1_ownership] ClusterMonitorTopo query error: {}".format(
                    self.root_id, self.ip, err
                )
            )
            return FactCheckOutcome(
                state=FactState.UNKNOWN,
                evidence={
                    **f1_evidence_base,
                    "cc_bk_module_ids": actual_bk_module_ids,
                    "resource_bk_module_id": resource_bk_module_id,
                    "error": str(err),
                    "trace": traceback.format_exc(limit=3),
                },
                error=str(err),
                reason="F1 ClusterMonitorTopo 查询异常：{}".format(err),
            )

        hit_cluster_module: bool = bool(dbm_matched_module_ids)

        # 2.5 汇总判定（严格版 · 判定 A ∨ 判定 B）
        # 判定 A · 资源池独占：CC 只有一个模块，且等于资源池模块 id
        #   → 机器"从未交付"或"已完全归还资源池"，视为本单管控内
        # 判定 B · DBM 集群子集：CC 每一个模块都在本 (bk_biz_id + db_type) 的 ClusterMonitorTopo 集群模块池内
        #   → 机器"已完整交付到本 db_type 集群模块下"，视为本单管控内
        # 其他一律 F1=NO（混合状态 / 越界 / 非法移动）
        hit_resource_only: bool = len(actual_bk_module_ids) == 1 and actual_bk_module_ids[0] == resource_bk_module_id
        hit_full_dbm_subset: bool = hit_cluster_module and set(actual_bk_module_ids).issubset(
            set(dbm_matched_module_ids)
        )

        f1_evidence_full: Dict[str, Any] = {
            **f1_evidence_base,
            "cc_bk_module_ids": actual_bk_module_ids,
            "resource_bk_module_id": resource_bk_module_id,
            "dbm_matched_module_ids": dbm_matched_module_ids,
            "cluster_type": unit.cluster_type,
            "allowed_machine_types": allowed_machine_types,
            "hit_resource_only": hit_resource_only,
            "hit_full_dbm_subset": hit_full_dbm_subset,
        }

        if hit_resource_only:
            return FactCheckOutcome(
                state=FactState.YES,
                evidence=f1_evidence_full,
                reason=("F1=YES：机器最近事件 ticket={} 与本单 apply parent_ticket={} 一致，" "且 CC 模块唯一且等于资源池模块 {}（未交付）").format(
                    last_event_ticket_id, parent_ticket_id, resource_bk_module_id
                ),
            )

        if hit_full_dbm_subset:
            return FactCheckOutcome(
                state=FactState.YES,
                evidence=f1_evidence_full,
                reason=(
                    "F1=YES：机器最近事件 ticket={} 与本单 apply parent_ticket={} 一致，"
                    "且 CC 模块 {} 全部落在本业务 db_type={} 的 DBM 集群模块池内"
                ).format(last_event_ticket_id, parent_ticket_id, actual_bk_module_ids, unit.cluster_type),
            )

        return FactCheckOutcome(
            state=FactState.NO,
            evidence=f1_evidence_full,
            reason=(
                "F1=NO：机器 CC 模块 {cc_modules} 既非独占资源池模块 {resource}，"
                "也未完全落在本业务 {biz} 的 db_type={ctype} 集群模块内（命中子集 {matched}），"
                "疑似非法移动或状态异常"
            ).format(
                cc_modules=actual_bk_module_ids,
                resource=resource_bk_module_id,
                biz=self.bk_biz_id,
                ctype=unit.cluster_type,
                matched=dbm_matched_module_ids,
            ),
        )

    def _extract_parent_ticket_id(self) -> int:
        """从 self.ticket.details 提取 parent_ticket（apply 原单据 id）。

        RECYCLE_APPLY_HOST 单据由 :meth:`Ticket.create_recycle_ticket` 创建，
        其 details 中的 ``parent_ticket`` 字段记录了发起主机回收的原 apply 单据 id。
        F1 判据必须用 parent_ticket 与 MachineEvent 记录的 ticket_id 比对，
        而不能用 RECYCLE 单据自身的 id（那是新单据、与 MachineEvent 永远不匹配）。

        :return: apply 原单据 id
        :raises RevokeFlowBaseException: details 非 dict / parent_ticket 缺失 / 非合法整数
            —— 契约违反场景，短路上抛让 pipeline FAILED，避免"F1 静默 NO 全部 SKIP"的假象
        """
        details = getattr(self.ticket, "details", None)
        if not isinstance(details, dict):
            raise RevokeFlowBaseException(
                "F1: ticket.details is not a dict (ticket_id={}, details_type={})".format(
                    self.ticket.id, type(details).__name__
                )
            )

        raw = details.get("parent_ticket")
        if raw is None:
            raise RevokeFlowBaseException(
                "F1: ticket.details['parent_ticket'] is missing (ticket_id={})".format(self.ticket.id)
            )

        try:
            return int(raw)
        except (TypeError, ValueError) as err:
            raise RevokeFlowBaseException(
                "F1: ticket.details['parent_ticket'] is not int-castable, got {!r} (ticket_id={}): {}".format(
                    raw, self.ticket.id, err
                )
            )

    def check_f2_traffic(
        self,
        unit: RevokeUnit,
        clb_regions: Optional[List[str]] = None,
    ) -> FactCheckOutcome:
        """F2 · 客户端流量红线判据：DNS / CLB 任一命中即 YES（红线保留）。

        怎么做（两个子判据并列跑）：
          - F2.a · DNS：调 :meth:`check_dns_mapping`；DNS 记录里出现 ``unit.expected_domains``
            中任一域名 → F2.a=YES；DNS 完全无本机记录 → F2.a=NO；DNS 接口异常 → F2.a=UNKNOWN
          - F2.b · CLB：调 :meth:`check_clb_mapping`；命中 → F2.b=YES；未命中 → F2.b=NO；
            未提供 region 视为 NO；CLB 查询异常 → F2.b=UNKNOWN

        聚合规则：
          - 两个子判据任一 YES → F2=YES（红线）
          - 两个子判据全 NO → F2=NO
          - 无 YES 但至少一个 UNKNOWN → F2=UNKNOWN

        说明：
          - 历史版本还有 F2.d（proxy 后端引用检查），因语义上属于"上游 proxy 反向依赖"，
            与 F2 单机"客户端流量"判据的抽象层次不一致；已从 F2 聚合链路中剥离。
            :meth:`_sub_check_f2d_proxy_backends` 方法本体保留，供后续独立场景复用。

        :param unit: 判定所属机器单元；须包含 expected_domains
        :param clb_regions: CLB 需检查的 region 列表；None / 空 → F2.b 判 NO（不 UNKNOWN）
        :return: :class:`FactCheckOutcome`；evidence 中携带各子判据的 state 与命中详情
        边界：
          - unit 类型不合法 -> 直接返回 UNKNOWN，避免误伤
          - unit.expected_domains 为空 → F2.a=NO（本机没预期绑域名，无所谓有没有 DNS 残留）
        """
        if not isinstance(unit, RevokeUnit):
            return FactCheckOutcome(
                state=FactState.UNKNOWN,
                error="unit is not RevokeUnit",
                reason="F2 输入 unit 类型非法",
            )

        # ---- F2.a · DNS ----
        f2a_state, f2a_ev = self._sub_check_f2a_dns(expected_domains=unit.expected_domains)

        # ---- F2.b · CLB ----
        f2b_state, f2b_ev = self._sub_check_f2b_clb(regions=clb_regions or [])

        # ---- 聚合 ----
        evidence: Dict[str, Any] = {
            F2_SUB_KEY_DNS: {"state": f2a_state.value, **f2a_ev},
            F2_SUB_KEY_CLB: {"state": f2b_state.value, **f2b_ev},
        }
        sub_states: Tuple[FactState, FactState] = (f2a_state, f2b_state)

        if FactState.YES in sub_states:
            hits = [name for name, s in zip((F2_SUB_KEY_DNS, F2_SUB_KEY_CLB), sub_states) if s == FactState.YES]
            return FactCheckOutcome(
                state=FactState.YES,
                evidence=evidence,
                reason="F2=YES：红线命中，子判据 {} 命中".format(hits),
            )
        if FactState.UNKNOWN in sub_states:
            unknowns = [
                name for name, s in zip((F2_SUB_KEY_DNS, F2_SUB_KEY_CLB), sub_states) if s == FactState.UNKNOWN
            ]
            return FactCheckOutcome(
                state=FactState.UNKNOWN,
                evidence=evidence,
                error="unknown sub-facts: {}".format(unknowns),
                reason="F2=UNKNOWN：无子判据命中 YES，但子判据 {} 无法确认".format(unknowns),
            )
        return FactCheckOutcome(
            state=FactState.NO,
            evidence=evidence,
            reason="F2=NO：DNS / CLB 均未命中，无客户端流量残留",
        )

    def _sub_check_f2a_dns(self, expected_domains: Tuple[str, ...]) -> Tuple[FactState, Dict[str, Any]]:
        """F2.a · DNS 子判据（内部辅助）。

        怎么做：
          - 复用 :meth:`check_dns_mapping` 拿到 IP 上所有 DNS 记录
          - 从 records 中筛选出 ``expected_domains`` 命中项；命中即 YES
          - 若 DNS 完全无本机记录 → NO；接口异常 → UNKNOWN

        :param expected_domains: 本单在本机预期绑定的域名列表
        :return: (state, evidence)；evidence 携带命中的域名列表与全部 dns 响应摘要
        边界：
          - expected_domains 为空 → 直接 NO（本机不该绑域名，无关注价值）
        """
        if not expected_domains:
            return FactState.NO, {"skipped": True, "reason": "本机无预期域名，F2.a 不适用"}

        r = self.check_dns_mapping()
        # r.reason_code == CHECK_ERROR -> UNKNOWN
        if r.reason_code == HostCheckReasonCode.CHECK_ERROR:
            return FactState.UNKNOWN, {"error": r.reason, "evidence": r.evidence}
        # r.reason_code == IP_NO_DNS_RECORD -> NO
        if r.reason_code == HostCheckReasonCode.IP_NO_DNS_RECORD:
            return FactState.NO, {"dns_records": []}
        # 有 DNS 记录：判断是否命中 expected_domains
        expected_set = set(expected_domains)
        records: List[Dict[str, Any]] = r.evidence.get("records", []) if isinstance(r.evidence, dict) else []
        matched: List[Dict[str, Any]] = [rec for rec in records if rec.get("domain_name") in expected_set]
        if matched:
            return FactState.YES, {"matched_records": matched, "expected_domains": list(expected_domains)}
        # 有别的域名但没命中本单预期 → 视作 NO（可能是别的单据的历史残留，不在本单红线范围）
        return FactState.NO, {
            "dns_records": records,
            "expected_domains": list(expected_domains),
            "matched_records": [],
        }

    def _sub_check_f2b_clb(self, regions: List[str]) -> Tuple[FactState, Dict[str, Any]]:
        """F2.b · CLB 子判据（内部辅助）。

        怎么做：
          - 复用 :meth:`check_clb_mapping` 判定本机 IP 是否在 CLB 后端
          - regions 空 → 直接 NO（不启用 CLB 检查）
          - CLB 命中 → YES；未命中 → NO；接口异常 → UNKNOWN

        :param regions: CLB 需检查的 region 列表
        :return: (state, evidence)
        边界：
          - regions 空视为 NO 而非 UNKNOWN（HA 场景通常不启用 CLB，避免误挂起）
        """
        if not regions:
            return FactState.NO, {"skipped": True, "reason": "未配置 CLB regions，F2.b 不启用"}

        r = self.check_clb_mapping(regions=regions)
        if r.reason_code == HostCheckReasonCode.CHECK_ERROR:
            return FactState.UNKNOWN, {"error": r.reason, "evidence": r.evidence}
        if r.reason_code == HostCheckReasonCode.IP_REGISTERED_IN_CLB:
            return FactState.YES, {"matched": r.evidence}
        # NO_REGION_INPUT / IP_NOT_REGISTERED_IN_CLB → NO
        return FactState.NO, {"evidence": r.evidence}

    def _sub_check_f2d_proxy_backends(
        self, unit: RevokeUnit, alive_proxies: List[Dict[str, Any]]
    ) -> Tuple[FactState, Dict[str, Any]]:
        """F2.d · proxy 后端引用子判据（内部辅助，仅 role=backend* 的机器调用）。

        怎么做：
          - 对每台 alive_proxies 的 admin 端口跑 ``DRSApi.proxyrpc SELECT * FROM backends``
          - 解析 backends 列表；命中 ``本机 IP:本单端口`` 任一组合 → YES
          - 全部 proxy 均未命中 → NO
          - 所有 RPC 均失败 → UNKNOWN

        :param unit: 判定所属机器（backend 类角色）
        :param alive_proxies: 本组内 F4=YES 的 proxy 描述列表，每项 keys: ip, admin_port, bk_cloud_id
        :return: (state, evidence)
        边界：
          - alive_proxies 为空 → NO（无 F4 存活的 proxy 无法查后端，视作"无 proxy 引用"）
          - proxy 返回 error_msg -> 该 proxy 记入 failed_proxies，继续查其他
          - 部分 proxy 成功但均未命中 且 有 failed → NO（成功的 proxy 都没引用则视作 NO）
        """
        if not alive_proxies:
            return FactState.NO, {"skipped": True, "reason": "无 F4 存活的 proxy，F2.d 视作 NO"}

        expected_ports: List[int] = list(unit.expected_ports)
        # 构造 "ip:port" 匹配集合
        expected_targets: set = {"{}:{}".format(unit.ip, p) for p in expected_ports}

        matched_hits: List[Dict[str, Any]] = []
        failed_proxies: List[Dict[str, Any]] = []
        queried_proxies: List[str] = []

        # 按 bk_cloud_id 分组批量发 RPC（DRSApi.proxyrpc 支持一次多个 address 但要求同 cloud_id）
        cloud_groups: Dict[int, List[str]] = {}
        for p in alive_proxies:
            proxy_addr = "{}:{}".format(p.get("ip"), p.get("admin_port"))
            cloud_id = int(p.get("bk_cloud_id", self.bk_cloud_id))
            cloud_groups.setdefault(cloud_id, []).append(proxy_addr)
            queried_proxies.append(proxy_addr)

        for cloud_id, addresses in cloud_groups.items():
            try:
                resp = DRSApi.proxyrpc(
                    {
                        "addresses": addresses,
                        "cmds": ["SELECT * FROM backends;"],
                        "force": False,
                        "bk_cloud_id": cloud_id,
                    }
                )
            except Exception as err:
                logger.warning(
                    "[HostRevokeChecker][{}][{}][check_f2_traffic.f2d] proxyrpc failed for cloud_id={} addresses={}: {}".format(
                        self.root_id, self.ip, cloud_id, addresses, err
                    )
                )
                for a in addresses:
                    failed_proxies.append({"address": a, "error": str(err)})
                continue

            if not isinstance(resp, list):
                for a in addresses:
                    failed_proxies.append({"address": a, "error": "resp not list"})
                continue

            for item in resp:
                if not isinstance(item, dict):
                    continue
                addr = item.get("address", "")
                err_msg = item.get("error_msg") or ""
                if err_msg:
                    failed_proxies.append({"address": addr, "error": err_msg})
                    continue
                # 解析 cmd_results 里的 backends 表
                cmd_results = item.get("cmd_results") or []
                for cr in cmd_results:
                    if not isinstance(cr, dict):
                        continue
                    for row in cr.get("table_data") or []:
                        if not isinstance(row, dict):
                            continue
                        # backends 表通常字段名为 address；容错读一下 "backend"
                        backend_addr = str(row.get("address") or row.get("backend") or "").strip()
                        if backend_addr in expected_targets:
                            matched_hits.append(
                                {
                                    "proxy_address": addr,
                                    "backend_address": backend_addr,
                                }
                            )

        if matched_hits:
            return FactState.YES, {
                "matched_hits": matched_hits,
                "queried_proxies": queried_proxies,
                "failed_proxies": failed_proxies,
            }
        # 无命中但全部 RPC 都失败 → UNKNOWN
        if failed_proxies and len(failed_proxies) >= len(queried_proxies):
            return FactState.UNKNOWN, {
                "failed_proxies": failed_proxies,
                "queried_proxies": queried_proxies,
                "error": "all proxy RPCs failed",
            }
        # 部分成功但均未命中 → NO
        return FactState.NO, {
            "queried_proxies": queried_proxies,
            "failed_proxies": failed_proxies,
            "expected_targets": sorted(expected_targets),
        }

    def check_f3_dbm_residue(self, unit: RevokeUnit) -> FactCheckOutcome:
        """F3 · DBM 元数据残留判据：Machine / ProxyInstance / StorageInstance / StorageInstanceTuple 任一命中即 YES。

        怎么做：
          - 查 :class:`Machine` 表本机记录；命中 → F3.d 存在
          - 查 :class:`ProxyInstance` / :class:`StorageInstance` 表本机 bk_host_id 相关记录，
            按 ``unit.expected_ports`` 精确过滤本单端口的实例（多实例场景避免误伤同机他单实例）
          - 查 :class:`StorageInstanceTuple` 表本机相关的主从关系记录
          - 任一有记录 → F3=YES，evidence 按需求文档 表 5 的键名分组记录命中的对象 ID / port

        :param unit: 判定所属机器单元（必填）；unit.expected_ports 用于精确过滤 instance，
            多实例场景下必须传入以避免整机误伤同机他单据实例
        :return: :class:`FactCheckOutcome`
        边界：
          - DB 查询异常 -> state=UNKNOWN，error 携带异常摘要
          - 全部四表均无本机相关记录 -> state=NO
          - unit.expected_ports 为空元组时视作"无端口约束"（当前 V2 场景不会走到这里，
            RevokeUnit 契约要求 expected_ports 非空）
        """
        if not isinstance(unit, RevokeUnit):
            return FactCheckOutcome(
                state=FactState.UNKNOWN,
                error="unit is not RevokeUnit",
                reason="F3 输入 unit 类型非法",
            )
        print(unit)
        expected_ports: Tuple[int, ...] = unit.expected_ports
        try:
            # ---- F3.d · Machine ----
            machine = Machine.objects.filter(bk_host_id=self.bk_host_id).first()
            machine_hit: Optional[Dict[str, Any]] = None
            if machine is not None:
                machine_hit = {
                    "bk_host_id": machine.bk_host_id,
                    "ip": machine.ip,
                    "machine_type": machine.machine_type,
                    "cluster_type": machine.cluster_type,
                }

            # ---- F3.a · ProxyInstance ----
            proxy_qs = ProxyInstance.objects.filter(machine__bk_host_id=self.bk_host_id)
            if expected_ports:
                proxy_qs = proxy_qs.filter(port__in=list(expected_ports))
            proxy_hits: List[Dict[str, Any]] = [{"id": p.pk, "port": p.port, "status": p.status} for p in proxy_qs]

            # ---- F3.a · StorageInstance ----
            storage_qs = StorageInstance.objects.filter(machine__bk_host_id=self.bk_host_id)
            if expected_ports:
                storage_qs = storage_qs.filter(port__in=list(expected_ports))
            storage_hits: List[Dict[str, Any]] = [
                {"id": s.pk, "port": s.port, "instance_role": s.instance_role, "status": s.status} for s in storage_qs
            ]

            # ---- F3.c · StorageInstanceTuple ----
            # 本机作为主(ejector) 或 作为从(receiver) 都算命中；
            # 分两次查再合并，避免引入额外的 Q import
            ejector_tuples = list(
                StorageInstanceTuple.objects.filter(ejector__machine__bk_host_id=self.bk_host_id).values_list(
                    "id", "ejector_id", "receiver_id"
                )
            )
            receiver_tuples = list(
                StorageInstanceTuple.objects.filter(receiver__machine__bk_host_id=self.bk_host_id).values_list(
                    "id", "ejector_id", "receiver_id"
                )
            )
            all_tuple_ids: set = set()
            tuple_hits: List[Dict[str, Any]] = []
            for tid, ej_id, rc_id in ejector_tuples + receiver_tuples:
                if tid in all_tuple_ids:
                    continue
                all_tuple_ids.add(tid)
                tuple_hits.append({"id": tid, "ejector_id": ej_id, "receiver_id": rc_id})

        except Exception as err:
            logger.warning(
                "[HostRevokeChecker][{}][{}][check_f3_dbm_residue] DB query error: {}".format(
                    self.root_id, self.ip, err
                )
            )
            return FactCheckOutcome(
                state=FactState.UNKNOWN,
                evidence={"bk_host_id": self.bk_host_id, "error": str(err)},
                error=str(err),
                reason="F3 元数据查询异常：{}".format(err),
            )

        evidence: Dict[str, Any] = {
            F3_EV_KEY_MACHINE: machine_hit,
            F3_EV_KEY_PROXIES: proxy_hits,
            F3_EV_KEY_STORAGES: storage_hits,
            F3_EV_KEY_TUPLES: tuple_hits,
        }
        if machine_hit is None and not proxy_hits and not storage_hits and not tuple_hits:
            return FactCheckOutcome(
                state=FactState.NO,
                evidence=evidence,
                reason="F3=NO：DBM 元数据无本机相关记录",
            )
        return FactCheckOutcome(
            state=FactState.YES,
            evidence=evidence,
            reason="F3=YES：DBM 元数据有残留（Machine={} Proxy={} Storage={} Tuple={}）".format(
                bool(machine_hit), len(proxy_hits), len(storage_hits), len(tuple_hits)
            ),
        )

    @staticmethod
    def check_f4_process(process_check_ctx_json: Optional[Dict[str, Any]], ip: str) -> FactCheckOutcome:
        """F4 · 进程存活判据：解析上游 :class:`MySQLHostProcessCheckComponent` 输出的 ``<ctx>`` JSON。

        怎么做：
          - 复用现有 :meth:`parse_process_check_result` 的规范化逻辑
          - 映射规则：
            * parse 结果 passed=True + reason_code=OK → F4=NO（无 MySQL 家族进程 LISTEN）
            * parse 结果 passed=False + reason_code=MYSQL_STILL_ALIVE → F4=YES（有进程）
            * parse 结果 passed=False + reason_code=CHECK_ERROR → F4=UNKNOWN（脚本自身报错/结构异常）

        :param process_check_ctx_json: 上游 bamboo 节点写入 trans_data 的 <ctx> JSON dict；
            None 时表示上游节点未执行 / 失败，视为 UNKNOWN
        :param ip: 目标主机 IP，用于日志与 evidence
        :return: :class:`FactCheckOutcome`
        边界：
          - process_check_ctx_json 为 None -> state=UNKNOWN，error="ctx_json is None"
          - 其他解析异常收敛为 UNKNOWN
        """
        if process_check_ctx_json is None:
            return FactCheckOutcome(
                state=FactState.UNKNOWN,
                evidence={"ip": ip, "error": "ctx_json is None"},
                error="ctx_json is None",
                reason="F4=UNKNOWN：上游进程检查节点未产出 ctx JSON",
            )

        r = HostRevokeChecker.parse_process_check_result(script_output_json=process_check_ctx_json, ip=ip)
        if r.reason_code == HostCheckReasonCode.OK:
            return FactCheckOutcome(
                state=FactState.NO,
                evidence={
                    "ip": ip,
                    "hits": r.evidence.get("hits", []),
                    "collect_tool": r.evidence.get("collect_tool"),
                },
                reason="F4=NO：主机无 MySQL 家族进程 LISTEN",
            )
        if r.reason_code == HostCheckReasonCode.MYSQL_STILL_ALIVE:
            return FactCheckOutcome(
                state=FactState.YES,
                evidence={
                    "ip": ip,
                    "hits": r.evidence.get("hits", []),
                    "collect_tool": r.evidence.get("collect_tool"),
                },
                reason="F4=YES：主机仍有 {} 个 MySQL 家族进程 LISTEN".format(len(r.evidence.get("hits", []))),
            )
        # CHECK_ERROR 或其他兜底 → UNKNOWN
        return FactCheckOutcome(
            state=FactState.UNKNOWN,
            evidence={"ip": ip, "parse_evidence": r.evidence},
            error=r.reason,
            reason="F4=UNKNOWN：{}".format(r.reason),
        )

    # ---------------- 需求 7：MySQL 主机进程存活检查结果解析 ----------------

    @staticmethod
    def parse_process_check_result(
        script_output_json: Dict[str, Any],
        ip: str,
    ) -> HostCheckResult:
        """将 shell 脚本 ``<ctx>`` 中的 JSON 解析为统一的 :class:`HostCheckResult`。

        设计要点 / 怎么做：
          - **纯函数**：不查 DB、不发 RPC、不写日志（日志由调用方 Service 承担）
          - **主机维度语义**：只判断整机是否还有 MySQL 家族进程 LISTEN，
            不再基于端口列表做 alive / missing / hijacked 三态判定
          - 三分支：check_error > mysql_still_alive > ok

        :param script_output_json: 从脚本 ``<ctx>...</ctx>`` 段提取并 ``json.loads`` 得到的 dict；
            合法结构包含以下字段：
              * ``found_mysql_procs`` (bool)  是否命中 MySQL 家族进程
              * ``hits`` (list[dict])         命中详情，每项含 port/pid/proc_name
              * ``collect_tool`` (str/null)   实际使用的采集工具（ss / netstat）
              * ``error`` (str/null)          脚本自身错误信息
        :param ip: 目标主机 IP，仅用于组装 reason 便于排查
        :return: :class:`HostCheckResult`，reason_code 取值见 :class:`HostCheckReasonCode`
        边界：
          - 入参非 dict -> CHECK_ERROR，evidence.raw_output 携带原始入参
          - ``script_output_json.error`` 非空 -> CHECK_ERROR（如非 root / 无 ss & netstat）
          - 缺 ``hits`` 键 / 非 list -> CHECK_ERROR
          - ``hits`` 数组内元素结构非法（缺 port / pid / proc_name，或 port/pid 非整数）
            -> CHECK_ERROR
          - hits 非空 -> MYSQL_STILL_ALIVE（passed=False）
          - hits 为空 且 error 为空 -> OK（passed=True）
        """
        # 步骤 0：入参兜底（本方法是纯函数，即使 script_output_json 为 None 也应给出 CHECK_ERROR）
        if not isinstance(script_output_json, dict):
            return HostCheckResult(
                passed=False,
                reason_code=HostCheckReasonCode.CHECK_ERROR,
                reason="[{}] 脚本输出不是合法 dict：type={}".format(ip, type(script_output_json).__name__),
                evidence={"raw_output": script_output_json},
            )

        collect_tool = script_output_json.get("collect_tool")

        # 步骤 1：脚本自身报 error（如非 root / ss & netstat 均缺失）
        script_error = script_output_json.get("error")
        if script_error:
            return HostCheckResult(
                passed=False,
                reason_code=HostCheckReasonCode.CHECK_ERROR,
                reason="[{}] 脚本自身报错：{}".format(ip, script_error),
                evidence={
                    "raw_output": script_output_json,
                    "collect_tool": collect_tool,
                },
            )

        # 步骤 2：hits 结构合法性
        hits = script_output_json.get("hits")
        if not isinstance(hits, list):
            return HostCheckResult(
                passed=False,
                reason_code=HostCheckReasonCode.CHECK_ERROR,
                reason="[{}] 脚本输出结构异常：缺 hits 键或非 list".format(ip),
                evidence={"raw_output": script_output_json},
            )

        # 步骤 3：hits 数组内每一项做结构校验，规整成 List[Dict]
        normalized_hits: List[Dict[str, Any]] = []
        for idx, item in enumerate(hits):
            if not isinstance(item, dict):
                return HostCheckResult(
                    passed=False,
                    reason_code=HostCheckReasonCode.CHECK_ERROR,
                    reason="[{}] hits[{}] 非 dict：{!r}".format(ip, idx, item),
                    evidence={"raw_output": script_output_json},
                )
            try:
                port_val: int = int(item["port"])
                pid_val: int = int(item["pid"])
            except (KeyError, TypeError, ValueError) as err:
                return HostCheckResult(
                    passed=False,
                    reason_code=HostCheckReasonCode.CHECK_ERROR,
                    reason="[{}] hits[{}] 缺 port/pid 或非整数：{}".format(ip, idx, err),
                    evidence={"raw_output": script_output_json},
                )
            proc_name = item.get("proc_name")
            if not isinstance(proc_name, str) or not proc_name:
                return HostCheckResult(
                    passed=False,
                    reason_code=HostCheckReasonCode.CHECK_ERROR,
                    reason="[{}] hits[{}] 缺 proc_name 或非字符串：{!r}".format(ip, idx, proc_name),
                    evidence={"raw_output": script_output_json},
                )
            normalized_hits.append({"port": port_val, "pid": pid_val, "proc_name": proc_name})

        # 保持稳定顺序：按 port 升序
        normalized_hits.sort(key=lambda x: (x["port"], x["pid"], x["proc_name"]))

        # 步骤 4：三分支收敛
        if normalized_hits:
            hit_pairs = ", ".join(
                "{p}({n},pid={pid})".format(p=h["port"], n=h["proc_name"], pid=h["pid"]) for h in normalized_hits
            )
            return HostCheckResult(
                passed=False,
                reason_code=HostCheckReasonCode.MYSQL_STILL_ALIVE,
                reason=("[{ip}] 主机仍有 {n} 个 MySQL 家族进程 LISTEN：{pairs}").format(
                    ip=ip, n=len(normalized_hits), pairs=hit_pairs
                ),
                evidence={
                    "collect_tool": collect_tool,
                    "hits": normalized_hits,
                },
            )

        # hits 为空 且 error 为空 -> OK
        return HostCheckResult(
            passed=True,
            reason_code=HostCheckReasonCode.OK,
            reason="[{ip}] 主机上未检测到 MySQL 家族进程 LISTEN".format(ip=ip),
            evidence={
                "collect_tool": collect_tool,
                "hits": [],
            },
        )
