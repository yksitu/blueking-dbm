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
    **统一的组内 IP 列表格式化函数**（`format_group_ips`）
  - 输出既用于 bamboo `act_name` / `sub_name`，也用于 Service 内日志的 `ips=` 主标识
  - 集中化的格式规则避免"三处各写一份、折叠阈值不一致"

设计要点：
  - **保留 `group.units` 原始顺序**（Extractor 保序，禁止在此处重排）
  - **折叠规则**（IP 数量 ≥ 阈值时）：`ip1,ip2,ip3,...(+N)`，N = 剩余数量
    * 阈值为 4：单元素 / 2 / 3 台机器时展示全部 IP，避免"3 台就折叠"造成信息丢失
  - **IP 之间用 `,` 分隔**（不加空格）：减少 act_name 总长度，控制在 80 字符以内
  - **本模块不做空校验**：空 units 场景由上层（`build_group_revoke_subflow`）
    的 `RevokeFlowBaseException` 拦截，本函数收到空 units 时返回空字符串

边界：
  - 空 units -> 返回空字符串 `""`（不 raise，交由上层判断）
  - IP 数量 ≤ 3 -> 展示全部 IP，不折叠
  - IP 数量 ≥ 4 -> 展示前 3 个 + `,...(+N)` 折叠标记
"""
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # 仅类型注解使用；运行时不导入以避免循环 import
    from backend.flow.engine.revoke.models import ResourceGroup


#: 组内 IP 折叠阈值：IP 数量 >= 本值时折叠为"前 3 个 + ...(+N)"
#: 取值 4 是为了让 1/2/3 台机器的场景仍能展示全量 IP，避免"3 台就折叠"造成信息缺失
_IPS_FOLD_THRESHOLD: int = 4

#: 折叠时保留展示的前缀 IP 数量；配合 `_IPS_FOLD_THRESHOLD` 使用
_IPS_FOLD_HEAD_KEEP: int = 3


def format_group_ips(group: "ResourceGroup") -> str:
    """将组内 IP 列表格式化为紧凑字符串（供 act_name / 日志共用）。

    功能说明：
      - 展开 `group.units` 提取 IP 列表，保留原始顺序
      - IP 数量 <= 3 时：`ip1,ip2,ip3`
      - IP 数量 >= 4 时：`ip1,ip2,ip3,...(+N)`，其中 N = 剩余机器数
      - IP 之间用 `,` 分隔，不加空格，控制总长

    :param group: 资源组；由 Extractor 保证 `group.units` 保序
    :return: 紧凑的 IP 列表字符串；空 units 场景返回 `""`

    边界：
      - `group.units` 为空 -> 返回空串（上层已在 build_group_revoke_subflow 处
        用 RevokeFlowBaseException 拦截，本函数不做额外空校验）
      - IP 数量为 1 -> 直接展示单 IP，不加省略号
      - `group.units` 中若存在空 ip 字符串 -> 一并保留原样输出（Extractor 已保证非空）

    示例：
      >>> format_group_ips(group_with_1_unit)   # 单 IP
      '1.1.1.1'
      >>> format_group_ips(group_with_3_units)  # 3 台不折叠
      '1.1.1.1,2.2.2.2,3.3.3.3'
      >>> format_group_ips(group_with_5_units)  # 5 台折叠
      '1.1.1.1,2.2.2.2,3.3.3.3,...(+2)'
    """
    if not group.units:
        return ""

    ips = [u.ip for u in group.units]
    if len(ips) < _IPS_FOLD_THRESHOLD:
        return ",".join(ips)

    # 折叠：前 _IPS_FOLD_HEAD_KEEP 个 + ,...(+N)
    head = ips[:_IPS_FOLD_HEAD_KEEP]
    remaining_count = len(ips) - _IPS_FOLD_HEAD_KEEP
    return "{},...(+{})".format(",".join(head), remaining_count)
