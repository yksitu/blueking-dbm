# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-DB管理系统(BlueKing-BK-DBM) available.
Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

TenDBSingle 部署单据主机退回顶层编排 · v2 · F 模型 + 一台一组绑定。

模块职责：
  - 承担 `MYSQL_SINGLE_APPLY` 单据 TERMINATED 后的主机退回顶层入口
  - 复用 HA v2 编排骨架（`MysqlHaApplyRevokeFlow._do_revoke_flow` / `_build_one_group_pipeline` /
    `_run_empty_pipeline`），仅通过覆盖 Extractor 类与日志标识完成 Single 场景接入

设计要点：
  - **零代码复制**：继承 HA v2 类，仅覆盖 3 个类属性（`EXTRACTOR_CLASS` / `_LOG_PREFIX` / `_REVOKE_KIND`），
    编排逻辑（Extractor 提取 → 每组合并子流程 → 并行执行 → 空组 empty pipeline）完全通过 super() 复用
  - **Single 场景特性**：一组资源固定 1 台机器（承载 M 个 Single 集群实例）；G1 天然一致、
    G2 天然不适用；判定核心（F1~F4）/ 决策矩阵 / 组决策 / 清理段全部与 HA 共用同一套代码
  - **集群元数据清理分派**：由 `group_cleanup.py._cleanup_cluster_meta` 按 `Cluster.cluster_type`
    分派到 `TenDBSingleClusterHandler.decommission`，本类无需关心

模块边界：
  - ticket_data 缺 apply_infos → Extractor 返回 [] → 走 empty pipeline 分支
  - 顶层异常兜底完全继承自 HA v2 类的 `revoke_flow` try/except
"""
from backend.flow.engine.bamboo.scene.mysql.revoke.mysql_ha_apply_revoke_flow_v2 import MysqlHaApplyRevokeFlow
from backend.flow.engine.revoke.extractors.mysql_single_apply import MysqlSingleApplyExtractor


class MysqlSingleApplyRevokeFlow(MysqlHaApplyRevokeFlow):
    """TenDBSingle 部署单据主机退回 · v2 · F 模型 + 一台一组绑定。

    构造入参与父类 :class:`MysqlHaApplyRevokeFlow` / :class:`RevokeFlowBase` 一致：
      - ``root_id``    子单据 flow_obj_id（由 :meth:`Ticket.get_inner_controller_func` 传入）
      - ``ticket_data`` 原单据（MYSQL_SINGLE_APPLY）的 ticket_data 字典

    使用方式：
      控制器函数 :func:`MySQLController.mysql_single_apply_scene` 通过
      ``@revoke_with(MysqlSingleApplyRevokeFlow)`` 装饰后自动接入。
      revoke 时由 :class:`CalcRecycleApplyHostParamBuilder` 反射拿到本类并触发 :meth:`revoke_flow`。

    线程安全：非线程安全（bamboo 单实例执行）
    边界：
      - 与 HA v2 版本一致，完全继承其 revoke_flow 顶层 try/except 兜底
    """

    #: Extractor 类：Single 场景专用 Extractor
    EXTRACTOR_CLASS = MysqlSingleApplyExtractor

    #: 日志前缀：区分 Single 场景日志
    _LOG_PREFIX: str = "MysqlSingleApplyRevokeFlow"

    #: revoke 接入类型标识：便于灰度期日志检索
    _REVOKE_KIND: str = "single"
