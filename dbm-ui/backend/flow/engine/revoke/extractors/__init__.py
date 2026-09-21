# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-DB管理系统(BlueKing-BK-DBM) available.
Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

主机退回资源池 · 单据专属 Extractor 集合。

模块职责：
  - 定义 Extractor 抽象基类 :class:`ApplyHostExtractor`
  - 各部署类单据类型（TenDBHA / TenDBSingle / TenDBCluster 等）实现自己的 Extractor 子类
  - Extractor 只负责从 ticket_data 提取 ResourceGroup 列表，不做任何判定或副作用

契约：
  - Extractor 只提取 apply_infos 里"本单从资源池新申领"的机器，不涉及老集群成员机
  - 机器角色由 Extractor 根据 ticket_data 字段名硬编码指定
  - 缺少关键字段时 Extractor 返回空列表并记录 ERROR 日志，不抛异常
"""
