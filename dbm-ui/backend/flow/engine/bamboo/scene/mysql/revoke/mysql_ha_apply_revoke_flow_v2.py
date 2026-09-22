# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-DB管理系统(BlueKing-BK-DBM) available.
Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

TenDBHA 部署单据主机退回顶层编排 · v2 · F 模型 + 一组资源绑定。

模块职责：
  - 承担 `MYSQL_HA_APPLY` 单据 TERMINATED 后的主机退回顶层入口
  - 编排"每 apply_info 一组，组间并行"的合并子流程（单 SubProcess 内 4 段串行）：
      · 段 1: 进程扫描（单 act 多 IP + APPEND）→ trans_data.host_process_check
      · 段 2: 组级判定（F1~F4 + G1/G2 + 决策矩阵）→ trans_data.group_verdict / group_verdict_decision
      · 段 3: 元数据+DNS 精确清理（非 GROUP_RECYCLE 自动 no-op）→ trans_data.pending_clear_ips
      · 段 4: 机器脚本清理（空则 no-op）
  - 与 v1 的 :class:`MySQLHAApplyRevokeFlow` 差异：
      * 判定用 F1~F4 三态判据 + G1/G2 组级判据 + 8 格决策矩阵，边界清晰、可穷举
      * 判定与清理解耦，中间不引入 Pause 节点，时效性有保障
      * 每组独立处理（一组挂起不影响其他组自动退回）
      * 判定框架完全通用（后续 Single / TenDBCluster 只需替换 Extractor 即可复用）

设计要点：
  - **顶层 try/except 兜底**：任何未处理异常 → 记 ERROR 日志 + 空 recycle_hosts 结束，
    避免阻塞 RECYCLE_APPLY_HOST 主单据（需求 9.4）
  - **接入版本标识日志**：入口打印 ``revoke_version=v2 ...`` 便于灰度期回溯（需求 9.3）
"""
import logging
import traceback
from typing import Any, Dict, List

from django.utils.translation import gettext as _

from backend.configuration.constants import DBType
from backend.db_services.ipchooser.constants import BkOsTypeCode
from backend.flow.engine.bamboo.scene.common.builder import Builder
from backend.flow.engine.revoke.atomic_subflows.resource_group_revoke_subflow import build_group_revoke_subflow
from backend.flow.engine.revoke.base import RevokeFlowBase
from backend.flow.engine.revoke.extractors.mysql_ha_apply import MysqlHaApplyExtractor
from backend.flow.engine.revoke.models import ResourceGroup
from backend.flow.engine.revoke.trans_data import RevokeTransData

logger = logging.getLogger("flow")

#: 接入版本标识：便于灰度期通过日志检索走 v1 / v2 分支的单据
_REVOKE_VERSION: str = "v2"


class MysqlHaApplyRevokeFlow(RevokeFlowBase):
    """TenDBHA 部署单据主机退回 · v2 · F 模型 + 一组资源绑定。

    构造入参与 :class:`RevokeFlowBase` 一致：
      - ``root_id``    子单据 flow_obj_id（由 :meth:`Ticket.get_inner_controller_func` 传入）
      - ``ticket_data`` 原单据（MYSQL_HA_APPLY）的 ticket_data 字典

    使用方式：
      控制器函数 :func:`MySQLController.mysql_ha_apply_scene` 通过
      ``@revoke_with(MysqlHaApplyRevokeFlow)`` 装饰后自动接入。
      revoke 时由 :class:`CalcRecycleApplyHostParamBuilder` 反射拿到本类并触发 :meth:`revoke_flow`。

    线程安全：非线程安全（bamboo 单实例执行）
    边界：
      - ticket_data 缺 apply_infos → Extractor 返回 [] → 记 INFO 日志正常结束
      - 任何未处理异常 → try/except 兜底记 ERROR 日志、trans_data.recycle_hosts=[]、正常结束
    """

    #: Extractor 类：子类可覆盖以复用本类的编排逻辑到其他部署类单据
    EXTRACTOR_CLASS = MysqlHaApplyExtractor

    #: 日志前缀：子类覆盖以在日志中区分单据类型（HA / Single / Cluster）
    _LOG_PREFIX: str = "MysqlHaApplyRevokeFlow"

    #: revoke 接入类型标识：便于灰度期通过日志检索区分不同类型部署单据的 revoke 走向
    _REVOKE_KIND: str = "ha"

    def revoke_flow(self) -> None:
        """执行 revoke 主链路：Extractor → 每组编排「4 段合并子流程」→ 并行运行。

        :return: None
        边界：
          - 顶层任何异常均在此处兜底：记 ERROR 日志 + 不阻塞主单据
        """
        try:
            self._do_revoke_flow()
        except Exception as err:
            logger.error(
                "[{}][{}] revoke_flow unexpected error: {}\n{}".format(
                    self._LOG_PREFIX, self.root_id, err, traceback.format_exc(limit=5)
                )
            )
            # 顶层兜底：不抛出，让 RECYCLE_APPLY_HOST 主单据继续走"无回收主机则 SKIPPED"路径

    def _do_revoke_flow(self) -> None:
        """真正执行 revoke 编排。异常由顶层 revoke_flow 兜底捕获。"""
        ticket_id: int = int(self.data.get("uid") or self.data.get("ticket_id") or 0)
        bk_biz_id: int = int(self.data.get("bk_biz_id") or 0)

        logger.info(
            "[{}][{}] revoke_version={} revoke_kind={} ticket_id={} bk_biz_id={} entering".format(
                self._LOG_PREFIX, self.root_id, _REVOKE_VERSION, self._REVOKE_KIND, ticket_id, bk_biz_id
            )
        )

        # ---- 1. Extractor 提取候选资源组 ----
        groups: List[ResourceGroup] = self.EXTRACTOR_CLASS().extract(self.data)
        if not groups:
            logger.info(
                "[{}][{}] revoke_version={} revoke_kind={} ticket_id={} no candidate group, exit".format(
                    self._LOG_PREFIX, self.root_id, _REVOKE_VERSION, self._REVOKE_KIND, ticket_id
                )
            )
            # 依然启动一个空 pipeline 以便下游从 trans_data.recycle_hosts 取到空列表
            self._run_empty_pipeline()
            return

        logger.info(
            "[{}][{}] revoke_version={} revoke_kind={} ticket_id={} groups_count={} extracted".format(
                self._LOG_PREFIX, self.root_id, _REVOKE_VERSION, self._REVOKE_KIND, ticket_id, len(groups)
            )
        )

        # ---- 2. 顶层 pipeline 并行编排每组的合并子流程 ----
        # 关键字段说明：
        #   - ``uid``：bamboo 框架契约字段，写入 FlowTree.uid / FlowNode.uid；数值 = ticket_id
        #   - ``ticket_type`` / ``created_by`` / ``bk_biz_id``：Builder.run_pipeline 写 FlowTree 时强依赖，
        #     必须从 self.data（即 revoke_flow 入参的 ticket_data）透传；否则 KeyError。
        #   - ``db_type`` / ``os_type``：供清理 Service（如 ClearMachineScript）用；不进 FlowTree。
        #   - ticket_id 不放 global_data：本 flow 内业务 Service 通过 build_group_revoke_subflow(ticket_id=)
        #     显式入参 + act.kwargs 传递，无需走 global_data；避免与 uid 冗余（数值等价）。
        global_data: Dict[str, Any] = {
            "uid": ticket_id,
            "bk_biz_id": bk_biz_id,
            "ticket_type": self.data["ticket_type"],
            "created_by": self.data.get("created_by") or self.data.get("operator") or "",
            "db_type": DBType.MySQL.value,
            "os_type": BkOsTypeCode.LINUX.value,
        }
        # 说明：trans_data.recycle_hosts 由 RevokeTransData 声明默认 []；
        # 清理 Service 通过 setattr(trans_data, "recycle_hosts", ...) 累计，
        # 无需在此处 global_data 中冗余声明
        top_pipeline = Builder(root_id=self.root_id, data=global_data)

        # 每组构造一个"计算 → 清理"合并子流程；顶层将各组子流程并行执行
        # 合并到同一 SubProcess 是必需的：跨 SubProcess 时 trans_data 无法回写
        group_sub_pipelines: List[Any] = [
            build_group_revoke_subflow(
                root_id=self.root_id,
                ticket_id=ticket_id,
                group=group,
                global_data=global_data,
            )
            for group in groups
        ]

        top_pipeline.add_parallel_sub_pipeline(sub_flow_list=group_sub_pipelines)

        logger.info(
            "[{}][{}] revoke_version={} revoke_kind={} launching pipeline with {} groups".format(
                self._LOG_PREFIX, self.root_id, _REVOKE_VERSION, self._REVOKE_KIND, len(groups)
            )
        )
        # 关键：显式注入 RevokeTransData 作为 trans_data 初值；否则子流程内
        # setattr(trans_data, dynamic_key, value) 会在 trans_data 为 None 时抛 AttributeError
        top_pipeline.run_pipeline(init_trans_data_class=RevokeTransData())

    def _run_empty_pipeline(self) -> None:
        """无候选组时启动一个仅包含空 recycle_hosts 的最小 pipeline。

        目的：即使无候选组，也需要让 CalcRecycleApplyHostParamBuilder.post_callback 拿到
        ``trans_data.recycle_hosts=[]`` 走"无回收主机则后续 flow SKIPPED"逻辑。

        :return: None
        """
        # 最简单实现：直接 return 不 run。CalcRecycleApplyHostParamBuilder.post_callback 里
        # 通过 self.ticket.current_flow().output_data 取值；如果 flow 没有输出会走 AppBaseException
        # 分支，进而调用 BaseTicketFlow.run_error_status_handler。
        # 但对"合法但空"的场景我们期望直接走"后续 flow SKIPPED"分支，因此至少需要一次 run_pipeline。
        # 用一个空活动节点占位即可。
        from backend.flow.plugins.components.collections.common.empty_node import EmptyNodeComponent

        global_data: Dict[str, Any] = {
            "uid": int(self.data.get("uid") or 0),
            "bk_biz_id": int(self.data.get("bk_biz_id") or 0),
            # FlowTree 强依赖字段：从 ticket_data 透传，否则 Builder.run_pipeline 会 KeyError
            "ticket_type": self.data["ticket_type"],
            "created_by": self.data.get("created_by") or self.data.get("operator") or "",
        }
        top_pipeline = Builder(root_id=self.root_id, data=global_data)
        top_pipeline.add_act(
            act_name=_("无候选资源组 · 空回收"),
            act_component_code=EmptyNodeComponent.code,
            kwargs={},
        )
        # 与主分支保持一致：显式注入 RevokeTransData 作为 trans_data 初值
        top_pipeline.run_pipeline(init_trans_data_class=RevokeTransData())
