# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-DB管理系统(BlueKing-BK-DBM) available.
Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

TenDBHA 部署单据 · 候选主机 Extractor。

模块职责：
  - 从 ``MYSQL_HA_APPLY`` 单据的 ticket_data 提取每个 apply_info 对应的 :class:`ResourceGroup`
  - 硬编码机器角色：``proxy_ip_list`` → role=proxy；``mysql_ip_list[0]`` → backend_master；``mysql_ip_list[1]`` → backend_slave
  - 端口计算依据 ``mysql_ha_apply_flow`` 一致：``min(inst_num, len(clusters))`` 个 (port_start + i)
  - 域名分配：proxy 绑 ``clusters[*].master``；backend_slave 绑 ``clusters[*].slave``；backend_master 不绑

设计参考：
  - ``backend/flow/engine/bamboo/scene/mysql/mysql_ha_apply_flow.py`` 的 ``deploy_mysql_ha_flow_with_manual``
  - 每 apply_info 一组，组间独立、组内绑定

模块边界：
  - ticket_data 缺关键字段 -> 返回 []，记 ERROR 日志
  - apply_infos 为空列表 -> 返回 []（正常场景）
  - 单个 apply_info 内 mysql_ip_list 不足 2 台 -> 跳过该 apply_info 并记 ERROR
"""
import logging
from typing import Any, Dict, List, Optional, Tuple

from backend.db_meta.enums import ClusterType
from backend.flow.engine.revoke.extractors.base import ApplyHostExtractor
from backend.flow.engine.revoke.models import ResourceGroup, RevokeUnit

logger = logging.getLogger("flow")

#: role 常量：与 HostRevokeChecker.check_f2_traffic 的 role.startswith("backend") 契约保持一致
ROLE_PROXY: str = "proxy"
ROLE_BACKEND_MASTER: str = "backend_master"
ROLE_BACKEND_SLAVE: str = "backend_slave"

#: proxy admin 端口的偏移量（proxy 部署惯例：admin_port = proxy_port + 1000）
_PROXY_ADMIN_PORT_OFFSET: int = 1000


class MysqlHaApplyExtractor(ApplyHostExtractor):
    """TenDBHA 部署单据的候选主机 Extractor。

    职责：
      - 遍历 ``ticket_data["apply_infos"]``，为每个 apply_info 产出一个 ResourceGroup
      - 每组机器角色硬编码（proxy / backend_master / backend_slave）
      - 端口按 ``start_proxy_port + i`` / ``start_mysql_port + i`` 展开，
        i ∈ range(min(inst_num, len(clusters)))

    使用方式：
      extractor = MysqlHaApplyExtractor()
      groups = extractor.extract(ticket_data)

    线程安全：是
    边界：
      - ticket_data 类型非 dict / 缺 apply_infos -> 记 ERROR 返回 []
      - 单个 apply_info 缺关键字段（proxy_ip_list / mysql_ip_list / clusters 等）-> 跳过该组，
        其他 apply_info 正常处理；不影响整个 revoke_flow 继续
      - mysql_ip_list 长度不足 2 -> 跳过该 apply_info（HA 部署至少需要 1 master + 1 slave 两台）
    """

    def extract(self, ticket_data: Dict) -> List[ResourceGroup]:
        """从 TenDBHA 部署单据 ticket_data 提取候选组列表。

        :param ticket_data: MYSQL_HA_APPLY 单据的 flow ticket_data
        :return: List[ResourceGroup]；解析失败或空列表返回 []
        边界见类 docstring
        """
        if not isinstance(ticket_data, dict):
            logger.error("[MysqlHaApplyExtractor] ticket_data is not dict: type={}".format(type(ticket_data).__name__))
            return []

        apply_infos = ticket_data.get("apply_infos")
        if not isinstance(apply_infos, list):
            logger.error(
                "[MysqlHaApplyExtractor] ticket_data.apply_infos missing or not list: {!r}".format(apply_infos)
            )
            return []

        start_proxy_port = ticket_data.get("start_proxy_port")
        start_mysql_port = ticket_data.get("start_mysql_port")
        inst_num = ticket_data.get("inst_num")
        bk_biz_id = ticket_data.get("bk_biz_id")

        # 类型规整（ticket_data 里可能是字符串）
        try:
            start_proxy_port_i: int = int(start_proxy_port)
            start_mysql_port_i: int = int(start_mysql_port)
            inst_num_i: int = int(inst_num)
            bk_biz_id_i: int = int(bk_biz_id)
        except (TypeError, ValueError) as err:
            logger.error("[MysqlHaApplyExtractor] ticket_data field types illegal: {}".format(err))
            return []

        groups: List[ResourceGroup] = []
        for idx, info in enumerate(apply_infos):
            group = self._extract_one_apply_info(
                apply_info=info,
                apply_info_idx=idx,
                start_proxy_port=start_proxy_port_i,
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
        start_proxy_port: int,
        start_mysql_port: int,
        inst_num: int,
        bk_biz_id: int,
    ) -> Optional[ResourceGroup]:
        """处理一个 apply_info，产出 ResourceGroup。

        :param apply_info: 单个 apply_info 字典
        :param apply_info_idx: apply_info 在 apply_infos 中的索引，用于组 group_id 构造
        :param start_proxy_port: ticket_data.start_proxy_port
        :param start_mysql_port: ticket_data.start_mysql_port
        :param inst_num: ticket_data.inst_num
        :param bk_biz_id: 业务 id
        :return: :class:`ResourceGroup`；关键字段缺失时返回 None
        边界：
          - proxy_ip_list / mysql_ip_list / clusters 任一非 list 或空 -> None
          - mysql_ip_list 长度 < 2 -> None（HA 至少 1 master + 1 slave）
        """
        if not isinstance(apply_info, dict):
            logger.error(
                "[MysqlHaApplyExtractor] apply_infos[{}] is not dict: {!r}".format(apply_info_idx, apply_info)
            )
            return None

        proxy_ip_list = apply_info.get("proxy_ip_list") or []
        mysql_ip_list = apply_info.get("mysql_ip_list") or []
        clusters = apply_info.get("clusters") or []

        if not isinstance(proxy_ip_list, list) or not proxy_ip_list:
            logger.error(
                "[MysqlHaApplyExtractor] apply_infos[{}].proxy_ip_list empty or non-list".format(apply_info_idx)
            )
            return None
        if not isinstance(mysql_ip_list, list) or len(mysql_ip_list) < 2:
            logger.error(
                "[MysqlHaApplyExtractor] apply_infos[{}].mysql_ip_list length < 2 (got {})".format(
                    apply_info_idx, len(mysql_ip_list) if isinstance(mysql_ip_list, list) else "non-list"
                )
            )
            return None
        if not isinstance(clusters, list) or not clusters:
            logger.error("[MysqlHaApplyExtractor] apply_infos[{}].clusters empty or non-list".format(apply_info_idx))
            return None

        # 计算实际部署端口数量（与 mysql_ha_apply_flow.py 对齐）
        actual_inst_count: int = min(inst_num, len(clusters))
        if actual_inst_count <= 0:
            logger.error(
                "[MysqlHaApplyExtractor] apply_infos[{}] actual_inst_count <= 0 (inst_num={} clusters={})".format(
                    apply_info_idx, inst_num, len(clusters)
                )
            )
            return None

        proxy_ports: Tuple[int, ...] = tuple(start_proxy_port + i for i in range(actual_inst_count))
        proxy_admin_ports: Tuple[int, ...] = tuple(p + _PROXY_ADMIN_PORT_OFFSET for p in proxy_ports)
        mysql_ports: Tuple[int, ...] = tuple(start_mysql_port + i for i in range(actual_inst_count))

        # 提取集群主/从域名列表（顺序对齐 clusters[*].master 与 clusters[*].slave）
        master_domains: List[str] = []
        slave_domains: List[str] = []
        for c in clusters:
            if isinstance(c, dict):
                if c.get("master"):
                    master_domains.append(c["master"])
                if c.get("slave"):
                    slave_domains.append(c["slave"])

        cluster_domains: Tuple[str, ...] = tuple(master_domains)

        # ---- 构造组内 units ----
        units: List[RevokeUnit] = []

        # Proxy 单元：一台机器多实例，绑定所有 master 域名
        for p in proxy_ip_list:
            if not isinstance(p, dict) or "ip" not in p or "bk_host_id" not in p:
                logger.error(
                    "[MysqlHaApplyExtractor] apply_infos[{}].proxy_ip_list item missing ip/bk_host_id: {!r}".format(
                        apply_info_idx, p
                    )
                )
                return None
            units.append(
                RevokeUnit(
                    ip=str(p["ip"]),
                    bk_host_id=int(p["bk_host_id"]),
                    bk_cloud_id=int(p.get("bk_cloud_id", 0)),
                    bk_biz_id=bk_biz_id,
                    role=ROLE_PROXY,
                    expected_ports=proxy_ports,
                    expected_admin_ports=proxy_admin_ports,
                    expected_domains=tuple(master_domains),
                    expected_cluster_domains=cluster_domains,
                    cluster_type=ClusterType.TenDBHA.value,
                )
            )

        # Backend master 单元（mysql_ip_list[0]）：不绑域名
        m = mysql_ip_list[0]
        if not isinstance(m, dict) or "ip" not in m or "bk_host_id" not in m:
            logger.error(
                "[MysqlHaApplyExtractor] apply_infos[{}].mysql_ip_list[0] missing ip/bk_host_id".format(apply_info_idx)
            )
            return None
        units.append(
            RevokeUnit(
                ip=str(m["ip"]),
                bk_host_id=int(m["bk_host_id"]),
                bk_cloud_id=int(m.get("bk_cloud_id", 0)),
                bk_biz_id=bk_biz_id,
                role=ROLE_BACKEND_MASTER,
                expected_ports=mysql_ports,
                expected_admin_ports=tuple(),  # backend 没有 admin 端口
                expected_domains=tuple(),  # master 不绑域名
                expected_cluster_domains=cluster_domains,
                cluster_type=ClusterType.TenDBHA.value,
            )
        )

        # Backend slave 单元（mysql_ip_list[1]）：绑 slave 域名
        s = mysql_ip_list[1]
        if not isinstance(s, dict) or "ip" not in s or "bk_host_id" not in s:
            logger.error(
                "[MysqlHaApplyExtractor] apply_infos[{}].mysql_ip_list[1] missing ip/bk_host_id".format(apply_info_idx)
            )
            return None
        units.append(
            RevokeUnit(
                ip=str(s["ip"]),
                bk_host_id=int(s["bk_host_id"]),
                bk_cloud_id=int(s.get("bk_cloud_id", 0)),
                bk_biz_id=bk_biz_id,
                role=ROLE_BACKEND_SLAVE,
                expected_ports=mysql_ports,
                expected_admin_ports=tuple(),
                expected_domains=tuple(slave_domains),
                expected_cluster_domains=cluster_domains,
                cluster_type=ClusterType.TenDBHA.value,
            )
        )

        # ---- 装配 group_id + context ----
        group_id: str = "apply_info_{}".format(apply_info_idx)
        context: Dict[str, Any] = {
            "apply_info_idx": apply_info_idx,
            "start_proxy_port": start_proxy_port,
            "start_mysql_port": start_mysql_port,
            "inst_num": inst_num,
            "actual_inst_count": actual_inst_count,
            "cluster_domain_pairs": [
                {"master": c.get("master"), "slave": c.get("slave"), "name": c.get("name")}
                for c in clusters
                if isinstance(c, dict)
            ],
        }

        return ResourceGroup(
            group_id=group_id,
            units=tuple(units),
            cluster_domains=cluster_domains,
            context=context,
        )
