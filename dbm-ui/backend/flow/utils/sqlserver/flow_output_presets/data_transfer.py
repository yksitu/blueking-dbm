# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-DB管理系统(BlueKing-BK-DBM) available.
Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

------------------------------------------------------------------------------

SQLServer 数据传输类摘要预设。

职责：
  - 描述"每个目标集群一行"的数据传输执行信息（定点构造 / 原地回档 / 全量迁移 / 增量迁移 / 数据导出）。
  - 通过 table_primary_key = "cluster_domain_and_port"（目标集群）保证节点重试对同一目标集群的
    重复上报走覆盖合并；一对多 DTS 场景按 dst_cluster_list 展开为多行。

数据源 / 调用通道：
  - 由 SQLServer 数据传输类流程节点（db_construct / dts / data_export）在传输动作完成后，
    经通用组件 :class:`SqlserverFlowOutputSummaryComponent`（preset="data_transfer"）写入。
  - 目标集群域名 / 主实例由 :meth:`BaseFlow.resolve_cluster_summary_info` 反查 db_meta 装配；
    源集群域名从单据参数（src_cluster）装配；导出场景无源集群，``source_cluster_domain`` 留空。

边界：
  - instance 字段走 BaseFlowOutputSerializer.InstanceField，格式必须为 IP:Port。
  - mode 由枚举 :class:`SqlserverDataTransferMode` 强约束，非法值直接被 ChoiceField 拒绝。
  - databases 为列表 / 映射时由调用方拼接为纯文本，禁止塞结构化数据。
"""

from django.utils.translation import gettext as _
from rest_framework import serializers

from backend.flow.utils.base.flow_output import BaseFlowOutputSerializer
from blue_krill.data_types.enum import EnumField, StrStructuredEnum


class SqlserverDataTransferMode(StrStructuredEnum):
    """SQLServer 数据传输模式枚举（对齐 :class:`SqlserverDataTransferSummarySerializer.mode` 字段）。

    功能说明：
      - 描述"一次数据传输"对应的模式类型；供前端在执行摘要 tab 展示"这一行到底做了什么"，
        并支持按 mode 分组 / 过滤。
      - 值为短字符串（写入 FlowSummary），label 经 ``gettext`` 即时求值为 str，符合摘要 JSON 落盘约束。

    取值：
      - ROLLBACK       ("rollback")       -> 定点构造：从备份按时间点恢复到目标集群（可跨集群）
      - ROLLBACK_LOCAL ("rollback_local") -> 原地回档：在源集群本地按时间点回档
      - FULL_MIGRATE   ("full_migrate")   -> 全量迁移：源集群数据全量同步到目标集群
      - INCR_MIGRATE   ("incr_migrate")   -> 增量迁移：日志级增量同步到目标集群
      - EXPORT         ("export")         -> 数据导出：按库导出数据文件

    边界：
      - 非枚举值 -> :class:`serializers.ChoiceField` 校验失败，节点显式失败，便于排障；
      - 未来若出现新的传输语义，直接在此追加新的枚举项即可。
    """

    ROLLBACK = EnumField("rollback", _("定点构造"))
    ROLLBACK_LOCAL = EnumField("rollback_local", _("原地回档"))
    FULL_MIGRATE = EnumField("full_migrate", _("全量迁移"))
    INCR_MIGRATE = EnumField("incr_migrate", _("增量迁移"))


class SqlserverDataTransferSummarySerializer(BaseFlowOutputSerializer):
    """SQLServer 数据传输摘要（每目标集群一行）。

    功能说明：
      - 描述集群维度的数据传输执行信息（构造 / 回档 / 迁移 / 导出），供前端在单据执行摘要 tab 中展示。
      - 通过 `table_primary_key = "cluster_domain_and_port"`（目标集群）让 FlowOutputHandler.insert_data
        在遇到相同目标集群的重复写入时走"后写覆盖前写"分支，天然幂等；
        一对多 DTS（一个源、多个目标）按目标集群展开为多行。

    输入参数（即 data 每一行的字段结构）：
      - cluster_domain_and_port (str, 必填, 非空): 目标集群主访问入口 `"domain:port"`，作为主键；
        导出场景即执行导出的集群本身
      - source_cluster_domain (str, 可空, 默认空串): 源集群域名；定点构造 / 迁移场景必填，
        原地回档可与目标相同，导出场景留空
      - instance (str, 必填, IP:Port): 执行实例标识——构造 / 迁移为目标集群 master，
        导出为按 select_role 选出的执行实例；格式由 InstanceField 强校验
      - databases (str, 必填, 非空): 传输库纯文本——无重命名为库列表（逗号分隔），
        有重命名为映射（如 "db1 -> db1_new"）
      - mode (str, 必填): 传输模式，取值必须在 :class:`SqlserverDataTransferMode` 枚举内
      - extra (str, 可空, 默认 ""): 传输附加信息兜底文本；前端按纯文本渲染。约定：
        rollback 承载 restore_time（恢复时间点），export 承载导出文件名与 select_role

    输出：
      - 写入 FlowSummary.summary 中 table_name = "sqlserver_data_transfer" 的表 values。

    边界：
      - cluster_domain_and_port / instance / databases / mode 缺失 -> is_valid 抛 ValidationError。
      - instance 非 IP:Port 格式 -> InstanceField.run_validators 抛校验异常。
      - mode 非枚举值 -> ChoiceField 抛校验异常。
      - 重复主键写入 -> 依赖 insert_data 主键合并分支覆盖旧行，行数不变。
    """

    #: 表名（sqlserver 命名空间下唯一，前缀 sqlserver_）
    table_name: str = "sqlserver_data_transfer"
    #: 前端表格展示名
    table_display_name: str = _("SQLServer 数据传输信息")
    #: 表主键：每目标集群一行，重复写入按 cluster_domain_and_port 覆盖合并
    table_primary_key: str = "cluster_domain_and_port"

    cluster_domain_and_port = serializers.CharField(
        help_text=_("目标集群主入口(domain:port)"), required=True, allow_blank=False
    )
    source_cluster_domain = serializers.CharField(help_text=_("源集群域名"), required=False, allow_blank=True, default="")
    databases = serializers.CharField(help_text=_("传输库列表或映射"), required=True, allow_blank=False)
    mode = serializers.ChoiceField(help_text=_("传输模式"), choices=SqlserverDataTransferMode.get_choices(), required=True)
    #: 传输附加信息兜底；前端按纯文本渲染，禁止塞 dict / list 结构化数据
    extra = serializers.CharField(help_text=_("扩展信息"), required=False, allow_blank=True, default="")
