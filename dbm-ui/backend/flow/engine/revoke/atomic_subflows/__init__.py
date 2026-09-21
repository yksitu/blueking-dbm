# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-DB管理系统(BlueKing-BK-DBM) available.
Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

主机退回资源池 · 通用两段式子流程集合。

模块职责：
  - 提供各部署类 / 非部署类单据 revoke_flow 复用的两段式子流程：
    * 计算子流程：F/G 判据采集 + 决策矩阵 → 输出 GroupVerdict 到 trans_data
    * 清理子流程：从 trans_data 读取 GroupVerdict → 按 evidence 精确执行清理动作
  - 顶层单据 revoke_flow 只负责组装 Extractor + 并行编排计算/清理子流程

契约：
  - 计算子流程绝不修改任何元数据、不做清理动作
  - 清理子流程严格按需求文档"表 5"顺序执行；任一步失败改判 GROUP_MANUAL 且不写 recycle_hosts
"""
