# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-DB管理系统(BlueKing-BK-DBM) available.
Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

Revoke 框架专用 role 字符串常量模块。

模块职责：
  - 收录 ``backend.db_meta.enums.InstanceRole`` 枚举未覆盖但 revoke 框架需共享的 access_layer
    角色字符串（proxy / spider）。
  - db_meta 已定义的 role（BACKEND_* / REMOTE_* / ORPHAN 等）一律直接用
    ``InstanceRole.<NAME>.value``，不在本模块重复声明。

边界：
  - 本模块不扩展为"所有 role 字符串统一注册表"；仅补齐 MySQL/TenDBCluster access_layer 缺口。
  - tdbctl 中控进程**不独立成 RevokeUnit**，与 SPIDER 共用 unit（通过 ``expected_ports`` 携带 ctl_port）。
"""

#: TenDBHA 的 proxy 接入层角色（mysql-proxy 进程）。
#: 不复用 ``InstanceRole.REDIS_PROXY`` 以避免 Redis 语义误导。
PROXY: str = "proxy"

#: TenDBCluster 的 spider 接入层角色。
#: spider 全系（master / 只读 slave / mnt）统一使用本角色；role 只驱动 host_check F2 路由
#: （路径 3 DNS + CLB），spider 全系判据行为一致，无需再细分。
#: expected_ports 统一仅含 spider 端口：db_meta 中 tdbctl 以同一 ProxyInstance 的 admin_port
#: 落库（port=spider_port），不存在 port=ctl_port 的实例记录。
SPIDER: str = "spider"
