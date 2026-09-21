# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-DB管理系统(BlueKing-BK-DBM) available.
Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

主机退回资源池 · 清理子流程 bamboo Service / Component。

模块职责：
  - :class:`ResourceGroupCleanupService` · 元数据+DNS 精确清理（按 evidence）
      * 非 GROUP_RECYCLE 结论直接 no-op 结束
      * GROUP_RECYCLE 结论：
        - 按 evidence.f2_traffic.f2a_dns 摘除 DNS 记录（本单端口 + 本机 IP）
        - 按 evidence.f3_dbm_residue.tuples 清 StorageInstanceTuple
        - 按 group.cluster_domains 循环清集群元数据（按 cluster_type 分派到 TenDBHA/TenDBSingle handler）
        - 按 evidence.f3_dbm_residue.machine/storages/proxies 清 Machine 元数据
        - 把 F4=YES 的机器 IP 写入 ``trans_data.pending_clear_ips``
        - 本组已清理机器通过 :class:`FlowOutputHandler(RecycleOutputContext.ToResourceSerializer)`
          追加到 FlowSummary（跨 SubProcess 天然共享；后续接手方从 FlowSummary 读取）
      * 任一清理步失败 -> 组决策改判 GROUP_MANUAL，本组机器不进 FlowSummary
  - :class:`ResourceGroupMachineClearService` · 机器脚本下发（继承自 ClearMachineScriptService）
      * 从 ``trans_data.pending_clear_ips`` 读 exec_ips
      * exec_ips 为空 -> 直接 return True 跳过
      * 非空 -> 回填 kwargs["exec_ips"] 后走父类 BkJobService 的 Job 下发 + 轮询逻辑

设计要点：
  - **判据 evidence = 清理清单**：判据里有什么才清什么，不做无差别清理
  - **元数据清理直接调 DB 层 API**（不走 bamboo 组件），因为这些是 python 层的同步操作，
    放在同一 Service 内可保证事务性和错误处理一致
  - **DNS 摘除也直接调 DnsApi**（DnsApi 是同步 HTTP，无需异步轮询）
  - **机器脚本下发必须走 Job API 异步**，所以拆一个专用组件复用 ClearMachineScriptService
  - **静态字段名**：与 :class:`RevokeTransData` 预声明字段一一对应；SubProcess 隔离保证组间无冲突
"""
import logging
from typing import Any, Dict, List, Optional, Set

from django.utils.translation import gettext as _
from pipeline.component_framework.component import Component

from backend.db_meta.api.cluster.tendbha.handler import TenDBHAClusterHandler
from backend.db_meta.api.cluster.tendbsingle.handler import TenDBSingleClusterHandler
from backend.db_meta.enums import ClusterType
from backend.db_meta.models import Cluster, StorageInstanceTuple
from backend.flow.consts import DBA_ROOT_USER
from backend.flow.engine.bamboo.scene.common.machine_os_init import RecycleOutputContext
from backend.flow.plugins.components.collections.common.base_service import BaseService
from backend.flow.plugins.components.collections.common.exec_clear_machine import ClearMachineScriptService
from backend.flow.utils.base.flow_output import FlowOutputHandler
from backend.flow.utils.dns_manage import DnsManage

logger = logging.getLogger("flow")

#: GROUP_RECYCLE 组决策字符串（与 GroupDecision.GROUP_RECYCLE.value 保持一致）
_GROUP_RECYCLE_VALUE: str = "group_recycle"


class ResourceGroupCleanupService(BaseService):
    """组级 · 元数据 + DNS 精确清理 Service。

    kwargs 契约（上层建节点时必须传入）：
      - ``bk_biz_id``         (int, 必填)  业务 id
      - ``cluster_domains``   (list[str], 必填)  本组承载的集群主域名列表
      - ``ips_display``       (str, 可选)  组内 IP 列表字符串（供日志主标识用；
        由 :func:`format_group_ips` 生成，与 act_name 保持一致）

    trans_data 输入（由段 2 :class:`ResourceGroupJudgeService` 写入）：
      - ``group_verdict``            asdict 序列化的 :class:`GroupVerdict` dict
      - ``group_verdict_decision``   :class:`GroupDecision` 的 .value 字符串

    trans_data 输出（供段 4 :class:`ResourceGroupMachineClearService` 消费）：
      - ``pending_clear_ips``   List[Dict{ip, bk_cloud_id}]，本组待清理机器
      - **外部落地**：本组已清理机器通过
        :class:`FlowOutputHandler(RecycleOutputContext.ToResourceSerializer)` 追加到
        FlowSummary 表（``@transaction.atomic + select_for_update``，跨组并发安全，
        天然累加）；不再走 ``trans_data.recycle_hosts``（SubProcess 隔离无法汇聚）。
        后续接手方从 FlowSummary 读取本次流程的"退回资源池"摘要。

    边界：
      - kwargs 关键字段缺失 -> log error 返回 False
      - group_verdict 缺失 / 非 GROUP_RECYCLE -> no-op 返回 True
      - 任一清理步失败 -> 记 ERROR 日志、组决策改判 GROUP_MANUAL、清空 pending_clear_ips、
        本组机器不进 FlowSummary；返回 True（保证不阻塞其他组）
      - FlowOutputHandler.insert_data 失败 -> 记 ERROR 日志但不改判、不阻塞：
        机器清理已完成，只是摘要表追加失败，人工兜底
    """

    def _execute(self, data, parent_data) -> bool:
        """按 group_verdict evidence 精确清理元数据 + DNS。

        :param data: bamboo 节点数据对象
        :param parent_data: bamboo 父节点数据对象（不使用）
        :return: True（Service 内异常收敛为组决策改判，不让节点整体失败）
        """
        kwargs: Dict[str, Any] = data.get_one_of_inputs("kwargs") or {}
        node_name: str = kwargs.get("node_name") or self.__class__.__name__
        bk_biz_id: Optional[int] = kwargs.get("bk_biz_id")
        cluster_domains: List[str] = kwargs.get("cluster_domains") or []
        # 组内 IP 列表字符串：与 act_name 一致，仅用于日志主标识（不参与业务逻辑）
        ips_display: str = kwargs.get("ips_display") or ""

        if not isinstance(bk_biz_id, int):
            self.log_error(_("[{}] kwargs 缺失关键字段 bk_biz_id").format(node_name))
            return False

        trans_data = data.get_one_of_inputs("trans_data")

        # ---- 1. 读组决策（静态字段：SubProcess 隔离保证组间无冲突）----
        gv_dict = getattr(trans_data, "group_verdict", None) if trans_data is not None else None
        decision: str = getattr(trans_data, "group_verdict_decision", "") if trans_data is not None else ""

        if not isinstance(gv_dict, dict) or not gv_dict:
            self.log_error(_("[{}] trans_data.group_verdict 缺失或非 dict，跳过清理").format(node_name))
            # 写空的 pending_clear_ips，避免下游取到默认零值时的语义不清
            if trans_data is not None:
                setattr(trans_data, "pending_clear_ips", [])
            return True

        if decision != _GROUP_RECYCLE_VALUE:
            self.log_info(
                _("[{}] ips=[{}] decision={}，非 GROUP_RECYCLE，跳过清理（no-op）").format(node_name, ips_display, decision)
            )
            if trans_data is not None:
                setattr(trans_data, "pending_clear_ips", [])
            return True

        # ---- 2. GROUP_RECYCLE：解析 verdicts 收集清理动作输入 ----
        verdicts: List[Dict[str, Any]] = gv_dict.get("verdicts") or []
        if not verdicts:
            self.log_error(_("[{}] group_verdict.verdicts 为空，跳过清理").format(node_name))
            if trans_data is not None:
                setattr(trans_data, "pending_clear_ips", [])
            return True

        self.log_info(
            _("[{}] 开始清理 ips=[{}] 单机数={} clusters={}").format(node_name, ips_display, len(verdicts), cluster_domains)
        )

        cleaned_hosts: List[Dict[str, Any]] = []
        pending_clear_ips: List[Dict[str, Any]] = []
        try:
            for v in verdicts:
                self._cleanup_one_host(v, node_name=node_name)
                unit_dict = v.get("unit") or {}
                ip_val = unit_dict.get("ip")
                bk_host_id_val = unit_dict.get("bk_host_id")
                bk_cloud_id_val = unit_dict.get("bk_cloud_id")
                # 追加到已清理列表；用于外部 FlowOutputHandler 落地
                # 防御：HostOutputSerializer 的 ip/bk_host_id/bk_cloud_id 为必填字段；任一缺失直接跳过防抛异常
                if ip_val and bk_host_id_val is not None and bk_cloud_id_val is not None:
                    cleaned_hosts.append(
                        {
                            "ip": ip_val,
                            "bk_host_id": bk_host_id_val,
                            "bk_cloud_id": bk_cloud_id_val,
                        }
                    )
                else:
                    self.log_error(_("[{}] verdict.unit 关键字段缺失，跳过入 FlowSummary；unit={}").format(node_name, unit_dict))
                # F4=YES 的机器进入待下发清理脚本队列
                f4_state = ((v.get("facts") or {}).get("f4_process") or {}).get("state")
                if f4_state == "yes":
                    pending_clear_ips.append(
                        {
                            "ip": unit_dict.get("ip"),
                            "bk_cloud_id": unit_dict.get("bk_cloud_id"),
                        }
                    )

            # ---- 3. 清理集群维度元数据（按每个 cluster_domain 调 handler.decommission）----
            for domain in cluster_domains:
                self._cleanup_cluster_meta(domain=domain, bk_biz_id=bk_biz_id, node_name=node_name)

        except Exception as err:
            self.log_error(
                _("[{}] 清理动作失败 ips=[{}] err={}，本组改判 GROUP_MANUAL，机器不进 FlowSummary").format(node_name, ips_display, err)
            )
            logger.exception(err)
            # 改判组决策（静态字段：SubProcess 隔离保证组间无冲突）
            if trans_data is not None:
                setattr(trans_data, "group_verdict_decision", "group_manual")
                setattr(trans_data, "pending_clear_ips", [])
            return True

        # ---- 4. 写入 pending_clear_ips，供下一节点消费 ----
        if trans_data is not None:
            setattr(trans_data, "pending_clear_ips", pending_clear_ips)

        # ---- 5. 本组可回收机器直接落地到 FlowSummary（跨组累加、跨 SubProcess 天然共享）----
        # 说明：
        #   - 不走 trans_data.recycle_hosts：SubProcess 天然隔离，跨组无法汇聚
        #   - 走 FlowOutputHandler(RecycleOutputContext.ToResourceSerializer).insert_data(...)：
        #     底层 @transaction.atomic + select_for_update；多组子流程并发追加天然安全；
        #     无主键 → 走 values.extend，多次调用天然累加
        #   - root_id 优先从 global_data["job_root_id"] 取（与旧惯例对齐），缺失时回退 self.root_id
        #   - cleaned_hosts 字段严格对齐 HostOutputSerializer（ip/bk_cloud_id/bk_host_id 必填）
        #   - TODO(后续): 该 handler 后续会重构，届时替换本段落地实现即可
        if cleaned_hosts:
            global_data: Dict[str, Any] = data.get_one_of_inputs("global_data") or {}
            root_id: str = global_data.get("job_root_id") or self.root_id
            try:
                FlowOutputHandler(RecycleOutputContext.ToResourceSerializer).insert_data(root_id, cleaned_hosts)
            except Exception as err:
                # insert_data 失败不阻塞主流程：机器已成功清理，只是"退回资源池摘要表"追加失败
                # 记 ERROR 供人工兜底；组决策不改判
                self.log_error(
                    _("[{}] 追加 ToResourceSerializer 失败 ips=[{}] err={}；机器清理已完成，需人工确认摘要表").format(
                        node_name, ips_display, err
                    )
                )
                logger.exception(err)

        self.log_info(
            _("[{}] 清理完成 ips=[{}] 已清理机器数={} 待下发脚本机器数={}").format(
                node_name, ips_display, len(cleaned_hosts), len(pending_clear_ips)
            )
        )
        return True

    def _cleanup_one_host(self, verdict_dict: Dict[str, Any], node_name: str) -> None:
        """清理一台机器的 F2/F3 类残留（DNS + StorageInstanceTuple + Machine 元数据）。

        :param verdict_dict: 单机 verdict dict（asdict 序列化的 RevokeVerdict）
        :param node_name: 日志前缀节点名
        :return: None
        边界：
          - 任一清理步失败会 raise 到上层，由上层做组决策改判
        """
        unit = verdict_dict.get("unit") or {}
        facts = verdict_dict.get("facts") or {}
        ip: str = unit.get("ip") or ""
        bk_host_id: int = int(unit.get("bk_host_id") or 0)
        bk_cloud_id: int = int(unit.get("bk_cloud_id") or 0)
        bk_biz_id: int = int(unit.get("bk_biz_id") or 0)
        expected_ports: List[int] = list(unit.get("expected_ports") or [])
        expected_domains: List[str] = list(unit.get("expected_domains") or [])

        # ---- F2.a DNS 摘除 ----
        f2a = ((facts.get("f2_traffic") or {}).get("evidence") or {}).get("f2a_dns") or {}
        matched_records = f2a.get("matched_records") or []
        if matched_records:
            self._recycle_dns_records(
                ip=ip,
                bk_biz_id=bk_biz_id,
                bk_cloud_id=bk_cloud_id,
                expected_ports=expected_ports,
                expected_domains=expected_domains,
                matched_records=matched_records,
                node_name=node_name,
            )

        # ---- F3.c StorageInstanceTuple 清理 ----
        tuples: List[Dict[str, Any]] = ((facts.get("f3_dbm_residue") or {}).get("evidence") or {}).get("tuples") or []
        if tuples:
            tuple_ids: List[int] = [int(t["id"]) for t in tuples if isinstance(t, dict) and "id" in t]
            if tuple_ids:
                deleted, _dels = StorageInstanceTuple.objects.filter(id__in=tuple_ids).delete()
                self.log_info(_("[{}] ip={} 清 StorageInstanceTuple {} 条").format(node_name, ip, deleted))

        # ---- F3.a/d Machine 元数据清理 ----
        f3_ev = (facts.get("f3_dbm_residue") or {}).get("evidence") or {}
        has_machine = bool(f3_ev.get("machine"))
        has_storages = bool(f3_ev.get("storages"))
        has_proxies = bool(f3_ev.get("proxies"))
        if has_machine or has_storages or has_proxies:
            self._clear_machine_meta(bk_host_id=bk_host_id, ip=ip, bk_cloud_id=bk_cloud_id, node_name=node_name)

    def _recycle_dns_records(
        self,
        ip: str,
        bk_biz_id: int,
        bk_cloud_id: int,
        expected_ports: List[int],
        expected_domains: List[str],
        matched_records: List[Dict[str, Any]],
        node_name: str,
    ) -> None:
        """摘除本机 IP + 本单端口对应的 DNS 记录。

        怎么做：
          - 按 F2.a evidence.matched_records 里的 (domain, port) 逐条摘除
          - 只摘除 domain ∈ expected_domains 且 port ∈ expected_ports 的记录
          - 使用 :class:`DnsManage` 的 recycle_domain_record 入口，与老实现一致

        :param ip: 主机 IP
        :param bk_biz_id: 业务 id，DnsManage 初始化必需
        :param bk_cloud_id: 云区域
        :param expected_ports: 本单端口列表（用于按 port 过滤 DNS 记录）
        :param expected_domains: 本单预期域名列表
        :param matched_records: 从 F2.a evidence 拿到的命中记录（每项含 domain_name / port）
        :param node_name: 日志前缀
        :return: None
        边界：
          - DnsApi 异常 -> raise 到上层
          - 无匹配的 (domain, port) 组合 -> 直接跳过，不发起 API
        """
        expected_ports_set: Set[int] = set(expected_ports)
        expected_domains_set: Set[str] = set(expected_domains)

        del_instance_list: List[str] = []
        matched_pairs: List[str] = []
        for rec in matched_records:
            domain: str = rec.get("domain_name") or ""
            port_val = rec.get("port")
            if domain not in expected_domains_set:
                continue
            try:
                port_int: int = int(port_val)
            except (TypeError, ValueError):
                continue
            if port_int not in expected_ports_set:
                continue
            del_instance_list.append("{}#{}".format(ip, port_int))
            matched_pairs.append("{}#{}@{}".format(ip, port_int, domain))

        if not del_instance_list:
            self.log_info(_("[{}] ip={} 无 DNS 记录需摘除").format(node_name, ip))
            return

        # 去重（同 ip#port 若被多域名解析引用只需摘一次）
        del_instance_list = sorted(set(del_instance_list))
        DnsManage(bk_biz_id=bk_biz_id, bk_cloud_id=bk_cloud_id).recycle_domain_record(
            del_instance_list=del_instance_list
        )
        self.log_info(
            _("[{}] 摘除 DNS ip={} instances={} pairs={}").format(node_name, ip, del_instance_list, matched_pairs)
        )

    def _clear_machine_meta(self, bk_host_id: int, ip: str, bk_cloud_id: int, node_name: str) -> None:
        """清理一台机器的 Machine + 实例元数据。

        直接调用 db_meta.api.machine.clear_info_for_machine，与老实现的 clear_machines 等价。

        :param bk_host_id: 主机 id
        :param ip: 主机 IP（仅日志用）
        :param bk_cloud_id: 云区域
        :param node_name: 日志前缀
        :return: None
        边界：
          - 底层 API 异常 -> raise 到上层
        """
        # 延迟 import 避免与 backend.db_meta.api 的循环 import 风险
        from backend.db_meta import api as db_meta_api

        db_meta_api.machine.clear_info_for_machine(
            machines=[{"ip": ip, "bk_host_id": bk_host_id, "bk_cloud_id": bk_cloud_id}]
        )
        self.log_info(_("[{}] 清 Machine 元数据 ip={} bk_host_id={}").format(node_name, ip, bk_host_id))

    def _cleanup_cluster_meta(self, domain: str, bk_biz_id: int, node_name: str) -> None:
        """清理集群维度元数据（TenDBHAClusterHandler.decommission）。

        与 :meth:`MySQLDBMeta.mysql_ha_destroy_for_revoke` 等价。

        :param domain: 集群主域名
        :param bk_biz_id: 业务 id
        :param node_name: 日志前缀
        :return: None
        边界：
          - Cluster 不存在 -> 记 INFO 日志跳过（可能是 F3.b 命中的是软状态或已被别的组清过）
          - 底层 decommission 异常 -> raise 到上层
        """
        try:
            cluster = Cluster.objects.get(immute_domain=domain, bk_biz_id=bk_biz_id)
        except Cluster.DoesNotExist:
            self.log_info(_("[{}] Cluster domain={} 已不存在，跳过").format(node_name, domain))
            return

        # 按 cluster_type 分派到对应集群 handler：
        #   * TenDBHA    -> TenDBHAClusterHandler.decommission
        #   * TenDBSingle -> TenDBSingleClusterHandler.decommission
        #   * 其他（含 TenDBCluster）→ 本次范围不处理，记 INFO 日志跳过
        if cluster.cluster_type == ClusterType.TenDBHA.value:
            self.log_info(
                _("[{}] 集群元数据清理分派 branch=TenDBHA domain={} cluster_id={}").format(node_name, domain, cluster.id)
            )
            TenDBHAClusterHandler(bk_biz_id=cluster.bk_biz_id, cluster_id=cluster.id).decommission()
            self.log_info(_("[{}] 清集群元数据 domain={} cluster_id={}").format(node_name, domain, cluster.id))
            return

        if cluster.cluster_type == ClusterType.TenDBSingle.value:
            self.log_info(
                _("[{}] 集群元数据清理分派 branch=TenDBSingle domain={} cluster_id={}").format(node_name, domain, cluster.id)
            )
            TenDBSingleClusterHandler(bk_biz_id=cluster.bk_biz_id, cluster_id=cluster.id).decommission()
            self.log_info(_("[{}] 清集群元数据 domain={} cluster_id={}").format(node_name, domain, cluster.id))
            return

        self.log_info(
            _("[{}] 集群元数据清理分派 branch=skipped domain={} type={} 非 TenDBHA/TenDBSingle，跳过").format(
                node_name, domain, cluster.cluster_type
            )
        )


class ResourceGroupCleanupComponent(Component):
    """组级 · 元数据 + DNS 精确清理 bamboo 组件。"""

    name = __name__
    code = "resource_group_cleanup"
    bound_service = ResourceGroupCleanupService


class ResourceGroupMachineClearService(ClearMachineScriptService):
    """组级 · 机器脚本清理 Service（继承自 ClearMachineScriptService，支持从 trans_data 动态取 exec_ips）。

    kwargs 契约：
      - 无必填字段；node_name / root_id / node_id 等由 add_act 自动注入

    trans_data 输入（由段 3 :class:`ResourceGroupCleanupService` 写入）：
      - ``pending_clear_ips``   List[Dict{ip, bk_cloud_id}]，本组待下发清理脚本的机器

    行为：
      - 从 ``trans_data.pending_clear_ips`` 读机器列表；空 -> 直接 return True 跳过
      - 非空 -> 回填 kwargs["exec_ips"] + kwargs["account_alias"] 后走父类逻辑

    边界：
      - trans_data.pending_clear_ips 缺失 / 空 -> 视作空列表跳过
      - 父类下发失败 -> 继承父类的 return False 语义
    """

    def _execute(self, data, parent_data) -> bool:
        """从 trans_data 静态字段回填 exec_ips 后走父类逻辑。

        :param data: bamboo 节点数据
        :param parent_data: 父节点数据
        :return: True 跳过 或 父类 _execute 结果
        """
        kwargs: Dict[str, Any] = data.get_one_of_inputs("kwargs") or {}
        node_name: str = kwargs.get("node_name") or self.__class__.__name__

        trans_data = data.get_one_of_inputs("trans_data")
        # 静态字段：SubProcess 隔离保证组间无冲突
        pending_ips = getattr(trans_data, "pending_clear_ips", None) if trans_data is not None else None
        if not pending_ips:
            self.log_info(_("[{}] trans_data.pending_clear_ips 为空，跳过机器脚本清理（no-op）").format(node_name))
            return True

        # 回填 kwargs 字段：exec_ips + account_alias
        kwargs["exec_ips"] = list(pending_ips)
        kwargs.setdefault("account_alias", DBA_ROOT_USER)

        # 走父类下发逻辑
        return super()._execute(data=data, parent_data=parent_data)


class ResourceGroupMachineClearComponent(Component):
    """组级 · 机器脚本清理 bamboo 组件。"""

    name = __name__
    code = "resource_group_machine_clear"
    bound_service = ResourceGroupMachineClearService
