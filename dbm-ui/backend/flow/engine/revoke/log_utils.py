# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-DB管理系统(BlueKing-BK-DBM) available.
Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

主机退回资源池 · 日志 / 节点名格式化辅助模块。

模块职责：
  - 为 `resource_group_revoke_subflow` / `group_judge` / `group_cleanup` 三处提供
    **统一的 IP 列表格式化 + 决策代号中文化**工具
  - 输出既用于 bamboo `act_name` / `sub_name`，也用于 Service 内日志的主标识

设计要点：
  - **不折叠 IP**：完整列出全部 IP（用 `, ` 分隔），保证 DBA 在流程节点树 / 日志里
    能看到所有涉及的机器；bamboo 前端已支持横向滚动，长文案不是问题
  - **代号中文化**：`SKIP / KEEP / RECYCLE / MANUAL` 等内部代号只在源码 / 告警关键字
    里保留，面向用户日志一律用中文短语（配合原代号括号注明，便于人工排查跨模块 grep）
  - **`extract_decision_reason` 剥离代号前缀**：`verdict.reason` 里携带的 `决策=SKIP：`
    这类前缀是给告警平台看的，日志里应只输出后半段"业务原因"
  - **本模块不做空校验**：空 units 场景由上层的 RevokeFlowBaseException 拦截

边界：
  - 空 units -> 返回空字符串 `""`（不 raise，交由上层判断）
  - 未知代号 -> 直接回退为代号原文（不 raise），避免因文案漏映射导致节点失败
"""
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # 仅类型注解使用；运行时不导入以避免循环 import
    from backend.flow.engine.revoke.models import ResourceGroup


#: 单机决策代号 → 中文短语映射（面向 DBA / SRE 阅读日志）
#: 对应 :class:`HostDecision` 的 4 个 value；命中不到时回退代号原文
HOST_DECISION_ZH: dict = {
    "skip": "跳过（不属于本单据）",
    "keep": "保留（仍在服务）",
    "recycle": "可清理",
    "manual": "挂起（需人工确认）",
}

#: 组决策代号 → 中文短语映射（面向 DBA / SRE 阅读日志）
#: 对应 :class:`GroupDecision` 的 4 个 value；命中不到时回退代号原文
GROUP_DECISION_ZH: dict = {
    "group_skip": "整组跳过",
    "group_keep": "整组保留",
    "group_recycle": "整组清理",
    "group_manual": "整组挂起",
}


def format_group_ips(group: "ResourceGroup") -> str:
    """将组内 IP 列表格式化为 `, ` 分隔的完整字符串（供 act_name / 日志共用）。

    功能说明：
      - 展开 `group.units` 提取 IP 列表，保留原始顺序
      - 全部 IP 完整列出，不折叠、不省略（DBA 需要看到所有涉及机器）
      - IP 之间用 `, ` 分隔（含空格，方便终端 / 前端换行显示时断词）

    :param group: 资源组；由 Extractor 保证 `group.units` 保序
    :return: 逗号空格分隔的 IP 列表字符串；空 units 场景返回 `""`

    边界：
      - `group.units` 为空 -> 返回空串（上层已在 build_group_revoke_subflow 处
        用 RevokeFlowBaseException 拦截，本函数不做额外空校验）
      - IP 数量为 1 -> 直接展示单 IP

    示例：
      >>> format_group_ips(group_with_1_unit)
      '1.1.1.1'
      >>> format_group_ips(group_with_4_units)
      '1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4'
    """
    if not group.units:
        return ""
    return ",\n ".join(u.ip for u in group.units)


def host_decision_zh(decision_value: str) -> str:
    """把单机决策代号（`skip` / `keep` / `recycle` / `manual`）转成中文短语。

    :param decision_value: :class:`HostDecision` 的 .value（小写字符串）
    :return: 中文短语；未知代号时回退代号原文
    """
    return HOST_DECISION_ZH.get(decision_value, decision_value)


def group_decision_zh(decision_value: str) -> str:
    """把组决策代号（`group_skip` / `group_keep` / `group_recycle` / `group_manual`）
    转成中文短语。

    :param decision_value: :class:`GroupDecision` 的 .value（小写字符串）
    :return: 中文短语；未知代号时回退代号原文
    """
    return GROUP_DECISION_ZH.get(decision_value, decision_value)


def extract_decision_reason(reason: str) -> str:
    """从 `verdict.reason` / `group_verdict.reason` 中剥离"决策=X："前缀，只保留业务原因。

    功能说明：
      - :class:`HostDecisionMatrix` 与 :class:`GroupDecisionMatrix` 产出的 reason 形如
        ``"决策=SKIP：机器已不属于本单据"`` / ``"组决策=GROUP_SKIP：组内全部机器均为 SKIP..."``
      - 面向用户日志里代号已单独中文化展示，reason 里再重复出现代号是噪音
      - 本函数按"首个中文冒号 `：`"切分，取右侧作为业务原因；若无冒号则返回原文

    :param reason: 原始 reason 字符串
    :return: 剥离代号前缀后的业务原因；未匹配前缀时返回原文（fail-safe）

    示例：
      >>> extract_decision_reason("决策=SKIP：机器已不属于本单据")
      '机器已不属于本单据'
      >>> extract_decision_reason("组决策=GROUP_MANUAL：G1=NO 组内单机结论不一致，构成 {...}")
      'G1=NO 组内单机结论不一致，构成 {...}'
      >>> extract_decision_reason("无冒号原文")
      '无冒号原文'
    """
    if not reason:
        return ""
    idx = reason.find("：")
    if idx < 0:
        return reason
    return reason[idx + 1 :].strip()
