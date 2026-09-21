# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-DB管理系统(BlueKing-BK-DBM) available.
Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

Extractor · 抽象基类。

模块职责：
  - 定义 :class:`ApplyHostExtractor` 抽象基类，规定各部署类单据 Extractor 的统一契约
  - 各部署类单据（TenDBHA / TenDBSingle / TenDBCluster 等）通过实现该基类
    完成从 ticket_data 到 :class:`ResourceGroup` 列表的转换

契约：
  - 只提取"本单从资源池申请到的新机器"，不含老集群成员机
  - 机器角色由 Extractor 根据 ticket_data 字段名硬编码指定
  - ticket_data 缺关键字段时返回空列表并记录 ERROR 日志，不抛异常
"""
import logging
from abc import ABC, abstractmethod
from typing import Dict, List

from backend.flow.engine.revoke.models import ResourceGroup

logger = logging.getLogger("flow")


class ApplyHostExtractor(ABC):
    """部署类单据 Extractor 抽象基类。

    职责：
      - 输入 ticket_data，输出 List[ResourceGroup]
      - 各具体子类负责根据本单据的 ticket_data schema 完成"字段名 → 机器 + 角色 + 端口 + 域名"的映射

    使用方式：
      extractor = MysqlHaApplyExtractor()
      groups = extractor.extract(ticket_data)  # -> List[ResourceGroup]

    线程安全：是（无实例状态）
    """

    @abstractmethod
    def extract(self, ticket_data: Dict) -> List[ResourceGroup]:
        """从 ticket_data 提取候选资源组列表。

        :param ticket_data: 原单据的完整 flow ticket_data（含 apply_infos / start_proxy_port 等字段）
        :return: List[ResourceGroup]；ticket_data 非法或空时返回 []
        边界：
          - 关键字段缺失 -> 返回空列表并记 ERROR 日志（不抛异常，避免阻塞主单据）
          - Extractor 输出的每个 ResourceGroup 必须至少包含 1 个 unit
          - 每个 unit 的 role 必须使用与 host_check.py 契约一致的字符串
            （proxy / backend_master / backend_slave / spider / spider_slave / remote_master / remote_slave / single）
        """
        raise NotImplementedError
