# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-DB管理系统(BlueKing-DBM) available.
Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

TenDBCluster 存储层重均衡单据（NODE_REBALANCE）· 候选主机 Extractor。

NODE_REBALANCE 与 MIGRATE_UPGRADE 的 ticket_data 完全同构（``cluster_id`` /
``remote_group[{master,slave}]`` / ``remote_shard_num``；mysql 端口同为
``range(20000, 20000 + remote_shard_num)``），两单据共用同一个 Extractor 实现
（见 ``migrate_upgrade.py``）；本模块只保留与单据类型对应的别名，供
``SpiderNodeRebalanceRevokeFlow`` 引用。
"""
from backend.flow.engine.bamboo.scene.spider.revoke.extractors.migrate_upgrade import (
    TenDBClusterMigrateUpgradeExtractor,
)

#: NODE_REBALANCE 单据的候选主机 Extractor：与迁移升级单据共用实现（同一对象的别名）
SpiderNodeRebalanceExtractor = TenDBClusterMigrateUpgradeExtractor
