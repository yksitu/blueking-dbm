# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-DB管理系统(BlueKing-BK-DBM) available.
Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

TenDBSingle 部署单据 · 候选主机 Extractor。

模块职责：
  - 从 ``MYSQL_SINGLE_APPLY`` 单据的 ticket_data 提取每个 apply_info 对应的 :class:`ResourceGroup`
  - 硬编码机器角色：``new_ip`` → role=single（Single 架构不含 proxy 层，也无主从）
  - 端口计算依据 ``mysql_single_apply_flow`` 一致：``min(inst_num, len(clusters))`` 个 (start_mysql_port + i)
  - 域名分配：single 机器绑 ``clusters[*].master``（Single 只有主域名，无 slave 域名）

设计参考：
  - ``backend/flow/engine/bamboo/scene/mysql/mysql_single_apply_flow.py`` 的 ``deploy_mysql_single_flow``
  - 每 apply_info 对应 1 台 single 机器 + M 个 Single 集群实例，作为一个 ResourceGroup
  - 一组一台，组间独立并行；G1（组内一致性）单元素天然成立，G2（集群架构完整性）不适用

模块边界：
  - ticket_data 缺关键字段 -> 返回 []，记 ERROR 日志
  - apply_infos 为空列表 -> 返回 []（正常场景）
  - 单个 apply_info 内 new_ip / clusters 缺失或非法 -> 跳过该 apply_info 并记 ERROR
"""
import logging
from typing import Any, Dict, List, Optional, Tuple

from backend.db_meta.enums import ClusterType
from backend.flow.engine.revoke.extractors.base import ApplyHostExtractor
from backend.flow.engine.revoke.models import ResourceGroup, RevokeUnit

logger = logging.getLogger("flow")

#: role 常量：与 ResourceGroup.get_master_units() 契约保持一致（"single" 属于 master 类角色，不属于 proxy 类）
ROLE_SINGLE: str = "single"


class MysqlSingleApplyExtractor(ApplyHostExtractor):
    """TenDBSingle 部署单据的候选主机 Extractor。

    职责：
      - 遍历 ``ticket_data["apply_infos"]``，为每个 apply_info 产出一个 ResourceGroup
      - 每组固定 1 个 RevokeUnit（single 机器承载 M 个 Single 集群实例）
      - 端口按 ``start_mysql_port + i`` 展开，i ∈ range(min(inst_num, len(clusters)))
      - 域名列表仅含 ``clusters[*].master``（Single 架构无 slave 域名）

    使用方式：
      extractor = MysqlSingleApplyExtractor()
      groups = extractor.extract(ticket_data)

    线程安全：是（无实例状态）
    边界：
      - ticket_data 类型非 dict / 缺 apply_infos -> 记 ERROR 返回 []
      - 单个 apply_info 缺关键字段（new_ip / clusters）-> 跳过该组，其他 apply_info 正常处理
      - actual_inst_count <= 0 -> 跳过该组（clusters 空或 inst_num <= 0）
    """

    def extract(self, ticket_data: Dict) -> List[ResourceGroup]:
        """从 TenDBSingle 部署单据 ticket_data 提取候选组列表。

        :param ticket_data: MYSQL_SINGLE_APPLY 单据的 flow ticket_data
        :return: List[ResourceGroup]；解析失败或空列表返回 []
        边界见类 docstring
        """
        if not isinstance(ticket_data, dict):
            logger.error(
                "[MysqlSingleApplyExtractor] ticket_data is not dict: type={}".format(type(ticket_data).__name__)
            )
            return []

        apply_infos = ticket_data.get("apply_infos")
        if not isinstance(apply_infos, list):
            logger.error(
                "[MysqlSingleApplyExtractor] ticket_data.apply_infos missing or not list: {!r}".format(apply_infos)
            )
            return []

        start_mysql_port = ticket_data.get("start_mysql_port")
        inst_num = ticket_data.get("inst_num")
        bk_biz_id = ticket_data.get("bk_biz_id")

        # 类型规整（ticket_data 里可能是字符串）
        try:
            start_mysql_port_i: int = int(start_mysql_port)
            inst_num_i: int = int(inst_num)
            bk_biz_id_i: int = int(bk_biz_id)
        except (TypeError, ValueError) as err:
            logger.error("[MysqlSingleApplyExtractor] ticket_data field types illegal: {}".format(err))
            return []

        groups: List[ResourceGroup] = []
        for idx, info in enumerate(apply_infos):
            group = self._extract_one_apply_info(
                apply_info=info,
                apply_info_idx=idx,
                start_mysql_port=start_mysql_port_i,
                inst_num=inst_num_i,
                bk_biz_id=bk_biz_id_i,
            )
            if group is not None:
                groups.append(group)
        return groups

    def _extract_one_apply_info(
        self,
        apply_info: Dict[str, Any],
        apply_info_idx: int,
        start_mysql_port: int,
        inst_num: int,
        bk_biz_id: int,
    ) -> Optional[ResourceGroup]:
        """处理一个 apply_info，产出 ResourceGroup。

        :param apply_info: 单个 apply_info 字典，形如 {"new_ip": {...}, "clusters": [...]}
        :param apply_info_idx: apply_info 在 apply_infos 中的索引，用于组 group_id 构造
        :param start_mysql_port: ticket_data.start_mysql_port
        :param inst_num: ticket_data.inst_num
        :param bk_biz_id: 业务 id
        :return: :class:`ResourceGroup`；关键字段缺失时返回 None
        边界：
          - new_ip 非 dict 或缺 ip/bk_host_id -> None
          - clusters 非 list 或空 -> None
          - actual_inst_count <= 0 -> None
        """
        if not isinstance(apply_info, dict):
            logger.error(
                "[MysqlSingleApplyExtractor] apply_infos[{}] is not dict: {!r}".format(apply_info_idx, apply_info)
            )
            return None

        new_ip = apply_info.get("new_ip")
        clusters = apply_info.get("clusters") or []

        if not isinstance(new_ip, dict) or "ip" not in new_ip or "bk_host_id" not in new_ip:
            logger.error(
                "[MysqlSingleApplyExtractor] apply_infos[{}].new_ip missing ip/bk_host_id: {!r}".format(
                    apply_info_idx, new_ip
                )
            )
            return None
        if not isinstance(clusters, list) or not clusters:
            logger.error(
                "[MysqlSingleApplyExtractor] apply_infos[{}].clusters empty or non-list".format(apply_info_idx)
            )
            return None

        # 计算实际部署端口数量（与 mysql_single_apply_flow.py 的 __calc_install_ports 完全对齐）
        actual_inst_count: int = min(inst_num, len(clusters))
        if actual_inst_count <= 0:
            logger.error(
                "[MysqlSingleApplyExtractor] apply_infos[{}] actual_inst_count <= 0 (inst_num={} clusters={})".format(
                    apply_info_idx, inst_num, len(clusters)
                )
            )
            return None

        mysql_ports: Tuple[int, ...] = tuple(start_mysql_port + i for i in range(actual_inst_count))

        # 提取集群主域名列表（Single 架构只绑主域名，无 slave 域名）
        master_domains: List[str] = []
        for c in clusters:
            if isinstance(c, dict) and c.get("master"):
                master_domains.append(c["master"])

        cluster_domains: Tuple[str, ...] = tuple(master_domains)

        # ---- 构造组内 units ----
        # TenDBSingle 一组只有 1 台机器（single 单节点，无 proxy、无 slave）
        try:
            unit = RevokeUnit(
                ip=str(new_ip["ip"]),
                bk_host_id=int(new_ip["bk_host_id"]),
                bk_cloud_id=int(new_ip.get("bk_cloud_id", 0)),
                bk_biz_id=bk_biz_id,
                role=ROLE_SINGLE,
                expected_ports=mysql_ports,
                expected_admin_ports=tuple(),  # Single 无 proxy 层，无 admin 端口
                expected_domains=cluster_domains,  # Single 只绑主域名
                expected_cluster_domains=cluster_domains,
                cluster_type=ClusterType.TenDBSingle.value,
            )
        except (TypeError, ValueError) as err:
            logger.error(
                "[MysqlSingleApplyExtractor] apply_infos[{}].new_ip field types illegal: {}".format(
                    apply_info_idx, err
                )
            )
            return None

        # ---- 装配 group_id + context ----
        group_id: str = "apply_info_{}".format(apply_info_idx)
        context: Dict[str, Any] = {
            "apply_info_idx": apply_info_idx,
            "start_mysql_port": start_mysql_port,
            "inst_num": inst_num,
            "actual_inst_count": actual_inst_count,
            "cluster_domain_pairs": [
                {"master": c.get("master"), "name": c.get("name")} for c in clusters if isinstance(c, dict)
            ],
        }

        return ResourceGroup(
            group_id=group_id,
            units=(unit,),
            cluster_domains=cluster_domains,
            context=context,
        )
