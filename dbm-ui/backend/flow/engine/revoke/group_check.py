# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-DB管理系统(BlueKing-BK-DBM) available.
Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

主机退回资源池 · 组级 G 判据采集器。

模块职责：
  - :class:`ResourceGroupChecker` 提供组级 G1 / G2 两条判据的采集方法
    * G1 · 组内一致性判据（纯本地聚合，无 IO）
    * G2 · 集群架构完整性判据（通过 DRSApi.proxyrpc 检查 proxy 后端指向）
  - 判据结果统一为 :class:`FactCheckOutcome`，供 :class:`GroupDecisionMatrix` 消费

设计要点：
  - **G1 是纯函数**：仅依赖组内单机 verdict，可 100% 单测
  - **G2 只启用于必要场景**：G1=YES + 组内均 RECYCLE + 组内有 F4=YES 的 proxy 与 backend；其他场景直接返回不适用
  - **RPC 失败保守偏 NO**：G2 所有 proxy RPC 全失败 → state=NO（保守不放行，避免误清）
  - **单一职责**：G 判据只做采集，决策映射交给 :class:`GroupDecisionMatrix`

模块边界：
  - 本模块不做清理动作
  - 不修改任何元数据、不写 FlowOutputHandler
"""
import logging
from typing import Any, Dict, List, Optional, Tuple

from backend.components import DRSApi
from backend.flow.engine.revoke.models import (
    FactCheckOutcome,
    FactState,
    GroupVerdict,
    HostDecision,
    ResourceGroup,
    RevokeVerdict,
)

logger = logging.getLogger("flow")


class ResourceGroupChecker:
    """组级 G 判据采集器。

    职责：
      - 汇总组内单机 verdict 产出 G1 判据（组内一致性）
      - 通过 proxy admin 端口 RPC 查 backends 产出 G2 判据（集群架构完整性）

    使用方式：
      checker = ResourceGroupChecker(root_id="root-xxx")
      g1 = checker.check_g1_consistency(verdicts)
      g2 = checker.check_g2_architecture(group, verdicts, alive_proxies=[...])

    线程安全：是（无实例可变状态）
    边界：
      - verdicts 为空 -> G1 判 UNKNOWN（不能确认一致性）
      - G2 触发条件不满足（G1!=YES / 组内非全 RECYCLE / 无 F4=YES 的 proxy/backend）
        -> 返回 None 表示"不适用"，调用方应据此传 None 给 GroupDecisionMatrix
    """

    def __init__(self, root_id: str) -> None:
        """:param root_id: flow root_id，用于日志追踪"""
        self.root_id: str = root_id

    # ---------------- G1 · 组内一致性 ----------------

    def check_g1_consistency(self, verdicts: Tuple[RevokeVerdict, ...]) -> FactCheckOutcome:
        """G1 · 组内一致性判据：组内所有机器结论完全一致则 YES。

        怎么做：
          - 收集组内所有单机 decision，若全部相等 → YES
          - 否则 → NO，evidence 记录具体构成

        :param verdicts: 组内单机 RevokeVerdict 序列
        :return: :class:`FactCheckOutcome`
        边界：
          - verdicts 为空 -> UNKNOWN（无法判定组一致性）
          - 全部一致（含全 MANUAL 的情况）也算 YES，但 GroupDecisionMatrix 会把
            "全 MANUAL 的 G1=YES" 视作"组内出现 MANUAL"（结论不属于 SKIP/KEEP/RECYCLE 三种），
            通过决策矩阵兜底走 GROUP_MANUAL
        """
        if not verdicts:
            return FactCheckOutcome(
                state=FactState.UNKNOWN,
                evidence={"reason": "verdicts is empty"},
                error="verdicts is empty",
                reason="G1=UNKNOWN：组内无 verdict，无法判定一致性",
            )

        decisions = [v.decision for v in verdicts]
        first = decisions[0]
        all_same = all(d == first for d in decisions)
        # 统计各结论数量，供 evidence 展示
        counter: Dict[str, int] = {}
        for d in decisions:
            counter[d.value] = counter.get(d.value, 0) + 1

        if all_same:
            return FactCheckOutcome(
                state=FactState.YES,
                evidence={"construction": counter, "unified_decision": first.value},
                reason="G1=YES：组内 {} 台机器结论一致（{}）".format(len(verdicts), first.value),
            )
        return FactCheckOutcome(
            state=FactState.NO,
            evidence={"construction": counter},
            reason="G1=NO：组内单机结论不一致，构成 {}".format(counter),
        )

    # ---------------- G2 · 集群架构完整性 ----------------

    def check_g2_architecture(
        self, group: ResourceGroup, verdicts: Tuple[RevokeVerdict, ...]
    ) -> Optional[FactCheckOutcome]:
        """G2 · 集群架构完整性判据：至少一台 proxy 的 backends 指向本组任一 backend_master。

        触发条件（同时满足才执行 RPC，否则返回 None 视作"不适用"）：
          1) 组内所有机器结论均为 RECYCLE（否则无需清理，检查无意义）
          2) 组内至少有一台 F4=YES 的 proxy（否则无法发起 proxyrpc）
          3) 组内至少有一台 F4=YES 的 backend_master（否则无匹配目标）

        判定逻辑：
          - 对每台 F4=YES 的 proxy 的 admin 端口跑 ``SELECT * FROM backends``
          - 检查返回的 backend 列表是否包含本组任一 backend_master 的 IP:本单端口
          - 至少一台 proxy 命中 → G2=YES
          - 所有 proxy RPC 全失败 → G2=NO（保守挂起）
          - 部分成功但均未命中 → G2=NO
          - 部分成功且至少一台命中 → G2=YES

        :param group: 判定所属资源组
        :param verdicts: 组内单机 RevokeVerdict 序列
        :return: :class:`FactCheckOutcome` 或 None（None = 不适用，跳过 G2 检查）
        边界：
          - 触发条件任一不满足 -> 返回 None
          - proxy RPC 全部异常 -> state=NO（不 UNKNOWN，保守挂起）
        """
        # ---- Step 1：触发条件校验（不满足则视作"不适用"）----
        precondition = self._g2_check_precondition(group, verdicts)
        if precondition is None:
            return None
        alive_proxies, alive_masters = precondition

        # ---- Step 2：构造期望匹配的 backend_master target 集合 ----
        expected_targets: set = {"{}:{}".format(m["ip"], port) for m in alive_masters for port in m["ports"]}

        # ---- Step 3：分 bk_cloud_id 分组发 proxyrpc ----
        cloud_groups: Dict[int, List[Dict[str, Any]]] = {}
        for p in alive_proxies:
            cloud_groups.setdefault(p["bk_cloud_id"], []).append(p)

        matched_hits: List[Dict[str, Any]] = []
        failed_proxies: List[Dict[str, Any]] = []
        queried_proxies: List[str] = []
        for cloud_id, proxies in cloud_groups.items():
            self._g2_rpc_one_cloud(
                group=group,
                cloud_id=cloud_id,
                proxies=proxies,
                expected_targets=expected_targets,
                queried_proxies=queried_proxies,
                matched_hits=matched_hits,
                failed_proxies=failed_proxies,
            )

        # ---- Step 4：结果聚合 ----
        return self._g2_finalize(
            expected_targets=expected_targets,
            queried_proxies=queried_proxies,
            matched_hits=matched_hits,
            failed_proxies=failed_proxies,
        )

    def _g2_check_precondition(
        self, group: ResourceGroup, verdicts: Tuple[RevokeVerdict, ...]
    ) -> Optional[Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]]:
        """G2 触发条件校验（辅助函数，降低主函数圈复杂度）。

        :param group: 资源组
        :param verdicts: 组内单机 verdict 序列
        :return: (alive_proxies, alive_masters) 二元组；不满足任一触发条件返回 None
        """
        if not verdicts:
            return None
        if not all(v.decision == HostDecision.RECYCLE for v in verdicts):
            return None

        alive_proxies: List[Dict[str, Any]] = self._collect_alive_proxies(group, verdicts)
        alive_masters: List[Dict[str, Any]] = self._collect_alive_masters(group, verdicts)
        if not alive_proxies or not alive_masters:
            logger.info(
                "[ResourceGroupChecker][{}][{}] G2 skipped: alive_proxies={}, alive_masters={}".format(
                    self.root_id, group.group_id, len(alive_proxies), len(alive_masters)
                )
            )
            return None
        return alive_proxies, alive_masters

    def _g2_rpc_one_cloud(
        self,
        group: ResourceGroup,
        cloud_id: int,
        proxies: List[Dict[str, Any]],
        expected_targets: set,
        queried_proxies: List[str],
        matched_hits: List[Dict[str, Any]],
        failed_proxies: List[Dict[str, Any]],
    ) -> None:
        """对单个云区域内的 proxy 批量发 proxyrpc，把结果追加到调用方三个累加列表。

        :param group: 资源组（仅用于日志）
        :param cloud_id: 本批 proxy 共享的 bk_cloud_id
        :param proxies: 本云区域内的 F4=YES proxy descriptor 列表
        :param expected_targets: 期望匹配的 backend_master target 字符串集合
        :param queried_proxies: [出参累加] 已发起 RPC 的 proxy address 列表
        :param matched_hits: [出参累加] 命中记录 [{proxy_address, backend_address}]
        :param failed_proxies: [出参累加] 失败记录 [{address, error}]
        :return: None（结果通过出参累加列表回传）
        边界：
          - proxyrpc 整批抛异常 -> 本批 proxy 全部计入 failed_proxies
          - resp 非 list -> 本批 proxy 全部计入 failed_proxies
          - 单个 proxy 的 error_msg 非空 -> 该 proxy 计入 failed_proxies
        """
        addresses = ["{}:{}".format(p["ip"], p["admin_port"]) for p in proxies]
        queried_proxies.extend(addresses)
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
                "[ResourceGroupChecker][{}][{}] G2 proxyrpc failed for cloud_id={} addresses={}: {}".format(
                    self.root_id, group.group_id, cloud_id, addresses, err
                )
            )
            for a in addresses:
                failed_proxies.append({"address": a, "error": str(err)})
            return

        if not isinstance(resp, list):
            for a in addresses:
                failed_proxies.append({"address": a, "error": "resp not list"})
            return

        for item in resp:
            if not isinstance(item, dict):
                continue
            self._g2_absorb_one_proxy_resp(
                item=item,
                expected_targets=expected_targets,
                matched_hits=matched_hits,
                failed_proxies=failed_proxies,
            )

    @staticmethod
    def _g2_absorb_one_proxy_resp(
        item: Dict[str, Any],
        expected_targets: set,
        matched_hits: List[Dict[str, Any]],
        failed_proxies: List[Dict[str, Any]],
    ) -> None:
        """吸收单台 proxy 的 proxyrpc 响应项，把命中 / 失败结果追加到累加列表。

        :param item: 单条 proxyrpc 响应 dict
        :param expected_targets: 期望匹配的 backend target 字符串集合
        :param matched_hits: [出参累加] 命中记录
        :param failed_proxies: [出参累加] 失败记录
        :return: None
        """
        addr = item.get("address", "")
        err_msg = item.get("error_msg") or ""
        if err_msg:
            failed_proxies.append({"address": addr, "error": err_msg})
            return
        cmd_results = item.get("cmd_results") or []
        for cr in cmd_results:
            if not isinstance(cr, dict):
                continue
            for row in cr.get("table_data") or []:
                if not isinstance(row, dict):
                    continue
                backend_addr = str(row.get("address") or row.get("backend") or "").strip()
                if backend_addr in expected_targets:
                    matched_hits.append({"proxy_address": addr, "backend_address": backend_addr})

    @staticmethod
    def _g2_finalize(
        expected_targets: set,
        queried_proxies: List[str],
        matched_hits: List[Dict[str, Any]],
        failed_proxies: List[Dict[str, Any]],
    ) -> FactCheckOutcome:
        """把 G2 累加结果映射为最终 :class:`FactCheckOutcome`。

        映射规则：
          - 全部 proxy RPC 失败 -> NO（保守挂起）
          - 至少一台命中 -> YES
          - 均未命中 -> NO

        :param expected_targets: 期望匹配的 backend target 集合
        :param queried_proxies: 已发起 RPC 的 proxy address 列表
        :param matched_hits: 命中记录
        :param failed_proxies: 失败记录
        :return: :class:`FactCheckOutcome`
        """
        evidence: Dict[str, Any] = {
            "expected_targets": sorted(expected_targets),
            "queried_proxies": queried_proxies,
            "matched_hits": matched_hits,
            "failed_proxies": failed_proxies,
        }

        # 所有 proxy RPC 都失败 → NO（保守挂起）
        if failed_proxies and len(failed_proxies) >= len(queried_proxies):
            return FactCheckOutcome(
                state=FactState.NO,
                evidence=evidence,
                reason="G2=NO：所有 proxy RPC 均失败，无法确认架构完整性（保守挂起）",
            )

        if matched_hits:
            return FactCheckOutcome(
                state=FactState.YES,
                evidence=evidence,
                reason="G2=YES：至少一台 proxy 的 backends 指向本组 backend_master（命中 {} 次）".format(len(matched_hits)),
            )

        return FactCheckOutcome(
            state=FactState.NO,
            evidence=evidence,
            reason="G2=NO：所有 proxy 的 backends 均未指向本组 backend_master",
        )

    # ---------------- 内部辅助 ----------------

    def _collect_alive_proxies(
        self, group: ResourceGroup, verdicts: Tuple[RevokeVerdict, ...]
    ) -> List[Dict[str, Any]]:
        """从组内选出所有 F4=YES 的 proxy 描述列表。

        怎么做：
          - 遍历 group.get_proxy_units()（含 proxy / spider / spider_slave / spider_mnt）
          - 只保留在 verdicts 中对应 F4=YES 的单元
          - 对每台 proxy 展开其 expected_admin_ports 为一条条 (ip, admin_port, bk_cloud_id)

        :param group: 资源组
        :param verdicts: 组内单机 verdict 序列
        :return: List[Dict{ip, admin_port, bk_cloud_id}]；空列表表示无存活 proxy
        """
        # 建立 ip -> verdict 索引，避免 O(N^2)
        verdict_by_ip: Dict[str, RevokeVerdict] = {v.unit.ip: v for v in verdicts}

        result: List[Dict[str, Any]] = []
        for unit in group.get_proxy_units():
            v = verdict_by_ip.get(unit.ip)
            if v is None or v.facts.f4_process.state != FactState.YES:
                continue
            # proxy 角色使用 expected_admin_ports；如果为空则用 expected_ports+1000 兜底
            admin_ports = list(unit.expected_admin_ports) or [p + 1000 for p in unit.expected_ports]
            for ap in admin_ports:
                result.append(
                    {
                        "ip": unit.ip,
                        "admin_port": ap,
                        "bk_cloud_id": unit.bk_cloud_id,
                    }
                )
        return result

    def _collect_alive_masters(
        self, group: ResourceGroup, verdicts: Tuple[RevokeVerdict, ...]
    ) -> List[Dict[str, Any]]:
        """从组内选出所有 F4=YES 的 backend_master（含 remote_master / single）描述列表。

        :param group: 资源组
        :param verdicts: 组内单机 verdict 序列
        :return: List[Dict{ip, ports, bk_cloud_id}]；空列表表示无存活 master
        """
        verdict_by_ip: Dict[str, RevokeVerdict] = {v.unit.ip: v for v in verdicts}
        result: List[Dict[str, Any]] = []
        for unit in group.get_master_units():
            v = verdict_by_ip.get(unit.ip)
            if v is None or v.facts.f4_process.state != FactState.YES:
                continue
            result.append(
                {
                    "ip": unit.ip,
                    "ports": list(unit.expected_ports),
                    "bk_cloud_id": unit.bk_cloud_id,
                }
            )
        return result


def build_group_warning_log(gv: GroupVerdict) -> str:
    """基于 GroupVerdict 生成 GROUP_MANUAL 场景下的结构化 WARNING 日志文本。

    职责：
      - 需求 6.3 / 10.4 · 组挂起时输出的告警日志内容
      - 便于告警平台按关键字捕获

    :param gv: 组级判定结论对象
    :return: 多行结构化日志字符串
    """
    lines: List[str] = []
    lines.append(
        "[REVOKE_GROUP_MANUAL] group_id={} decision={} reason={}".format(
            gv.group.group_id, gv.decision.value, gv.reason
        )
    )
    lines.append("  G1: state={} reason={}".format(gv.g1.state.value, gv.g1.reason))
    if gv.g2 is not None:
        lines.append("  G2: state={} reason={}".format(gv.g2.state.value, gv.g2.reason))
    else:
        lines.append("  G2: skipped (不适用)")
    for v in gv.verdicts:
        lines.append(
            "  host ip={} bk_host_id={} role={} decision={} F1={} F2={} F3={} F4={} reason={}".format(
                v.unit.ip,
                v.unit.bk_host_id,
                v.unit.role,
                v.decision.value,
                v.facts.f1_ownership.state.value,
                v.facts.f2_traffic.state.value,
                v.facts.f3_dbm_residue.state.value,
                v.facts.f4_process.state.value,
                v.reason,
            )
        )
    return "\n".join(lines)
