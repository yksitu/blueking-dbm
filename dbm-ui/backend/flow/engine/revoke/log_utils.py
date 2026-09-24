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
    """从 `verdict.reason` / `group_verdict.reason` 中剥离"决策=X："前缀 + 清洗 F/G 代号。

    功能说明：
      - :class:`HostDecisionMatrix` 与 :class:`GroupDecisionMatrix` 产出的 reason 形如
        ``"决策=RECYCLE：F1=YES F2=NO F4=no，按 F3 evidence 精确清理"``
        ``"组决策=GROUP_MANUAL：G1=NO 组内单机结论不一致..."``
      - 面向用户日志里代号已单独中文化展示，reason 里再出现 F1/F2/F3/F4/G1/G2 是噪音
      - 本函数分两步清洗：
          1) 按"首个中文冒号 `：`"切分，取右侧作为业务原因（剥离 `决策=X：` 前缀）
          2) 用固定映射把 reason 里的 F/G 代号替换为业务白话

    :param reason: 原始 reason 字符串
    :return: 剥离前缀 + 清洗代号后的业务原因；未匹配前缀时对原文做代号清洗后返回

    示例：
      >>> extract_decision_reason("决策=RECYCLE：F1=YES F2=NO F4=no，按 F3 evidence 精确清理")
      '归属本单据，无 DNS/CLB 绑定，无进程，按元数据残留证据精确清理'
      >>> extract_decision_reason("组决策=GROUP_MANUAL：G1=NO 组内单机结论不一致")
      '组内结论不一致'
    """
    if not reason:
        return ""
    # 步骤 1：剥离前缀（"决策=X：" / "组决策=Y："）
    idx = reason.find("：")
    body = reason[idx + 1 :].strip() if idx >= 0 else reason

    # 步骤 2：F/G 代号 → 业务白话（顺序敏感：先长后短，避免部分匹配）
    # 说明：这里的替换只影响面向用户的日志输出，不影响 verdict.reason 原文
    #      （告警平台 / 单测 grep 仍可用原代号定位）
    replacements: list = [
        # G 判据（放最前，避免被 F 判据模式误匹配）
        ("G1=YES", "组内结论一致"),
        ("G1=NO", "组内结论不一致"),
        ("G1=UNKNOWN", "组内一致性未知"),
        # F 判据
        ("F1=YES", "归属本单据"),
        ("F1=NO", "已被非法移动/重新入池"),
        ("F1=UNKNOWN", "归属状态未知"),
        ("F2=YES", "有 DNS/CLB 绑定"),
        ("F2=NO", "无 DNS/CLB 绑定"),
        ("F2=UNKNOWN", "DNS/CLB 绑定状态未知"),
        ("F3=YES", "有元数据残留"),
        ("F3=NO", "无元数据残留"),
        ("F3=UNKNOWN", "元数据残留状态未知"),
        ("F4=YES", "进程存活"),
        ("F4=NO", "无进程"),
        ("F4=UNKNOWN", "进程状态未知"),
        # 兼容 decision.py 里对 F4 小写 yes/no（历史遗留写法）
        ("F4=yes", "进程存活"),
        ("F4=no", "无进程"),
        # 固定短语（放最后，避免 F3 代号已被替换后再匹配失效）
        ("按 F3 evidence 精确清理", "按元数据残留证据精确清理"),
    ]
    for old, new in replacements:
        body = body.replace(old, new)
    return body


# ==========================================================================
# F/G 判据 state 值 → 业务白话映射（供单机日志"检测项"段落使用）
# --------------------------------------------------------------------------
# 使用场景：面向用户的判据结果输出（"是 / 否 / 未知" 三态白话），配合固定检测项
# 名称一起展示，让 DBA / SRE 一眼看懂"检测了什么、结果如何"，避免代号泄露。
# 输入统一为 :class:`FactState` 的 .value 字符串（yes / no / unknown），
# 未知代号 fail-safe 回退代号原文。
# ==========================================================================


#: F1 · 是否存在非法移动/重新入池
#: state=YES 表示"归属本单据（正常）" -> 面向用户是"否（不存在非法移动）"
#: state=NO 表示"不归属本单据（异常）" -> 面向用户是"是（存在非法移动/重新入池）"
F1_STATE_ZH: dict = {
    "yes": "否",
    "no": "是",
    "unknown": "未知",
}

#: F2 · 是否绑定 DNS 或 CLB 服务
#: state=YES 表示"有 DNS/CLB 引用（红线）" -> "是"
#: state=NO 表示"无 DNS/CLB 引用" -> "否"
F2_STATE_ZH: dict = {
    "yes": "是",
    "no": "否",
    "unknown": "未知",
}

#: F3 · 是否有元数据残留
#: state=YES 表示"存在元数据残留" -> "有"
F3_STATE_ZH: dict = {
    "yes": "有",
    "no": "无",
    "unknown": "未知",
}

#: F4 · 进程是否存活
#: state=YES 表示"本单端口进程仍在跑" -> "有"
F4_STATE_ZH: dict = {
    "yes": "有",
    "no": "无",
    "unknown": "未知",
}

#: G1 · 组内单机结论一致性
G1_STATE_ZH: dict = {
    "yes": "一致",
    "no": "不一致",
    "unknown": "未知",
}


def f1_zh(state_value: str) -> str:
    """F1 · 是否存在非法移动/重新入池 · state → 白话。

    :param state_value: :class:`FactState` 的 .value（yes / no / unknown）
    :return: 面向用户的白话（"否" / "是" / "未知"）；未知代号回退原文
    """
    return F1_STATE_ZH.get(state_value, state_value)


def f2_zh(state_value: str) -> str:
    """F2 · 是否绑定 DNS 或 CLB 服务 · state → 白话。

    :param state_value: :class:`FactState` 的 .value（yes / no / unknown）
    :return: 面向用户的白话（"是" / "否" / "未知"）；未知代号回退原文
    """
    return F2_STATE_ZH.get(state_value, state_value)


def f3_zh(state_value: str) -> str:
    """F3 · 是否有元数据残留 · state → 白话。

    :param state_value: :class:`FactState` 的 .value（yes / no / unknown）
    :return: 面向用户的白话（"有" / "无" / "未知"）；未知代号回退原文
    """
    return F3_STATE_ZH.get(state_value, state_value)


def f4_zh(state_value: str) -> str:
    """F4 · 进程是否存活 · state → 白话。

    :param state_value: :class:`FactState` 的 .value（yes / no / unknown）
    :return: 面向用户的白话（"有" / "无" / "未知"）；未知代号回退原文
    """
    return F4_STATE_ZH.get(state_value, state_value)


def g1_zh(state_value: str) -> str:
    """G1 · 组内单机结论一致性 · state → 白话。

    :param state_value: :class:`FactState` 的 .value（yes / no / unknown）
    :return: 面向用户的白话（"一致" / "不一致" / "未知"）；未知代号回退原文
    """
    return G1_STATE_ZH.get(state_value, state_value)
