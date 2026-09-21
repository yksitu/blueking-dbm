# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-DB管理系统(BlueKing-BK-DBM) available.
Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

MysqlSingleApplyExtractor 单元测试。

测试职责：
  - 覆盖需求 1（TenDBSingle 资源组抽取）全部验收标准 1.1~1.7
  - 覆盖成功标准 6：单实例 / 多实例 / 多组独立 / 半合法场景
  - 断言字段：role="single" / expected_admin_ports 为空 / expected_domains 仅含 master
    域名 / cluster_type = TenDBSingle
"""
from backend.db_meta.enums import ClusterType
from backend.flow.engine.revoke.extractors.mysql_single_apply import ROLE_SINGLE, MysqlSingleApplyExtractor


def _make_ticket_data(
    apply_infos_count: int = 1,
    inst_num: int = 2,
    clusters_per_apply: int = 3,
    start_mysql_port: int = 20000,
) -> dict:
    """构造合法的 MYSQL_SINGLE_APPLY ticket_data。

    :param apply_infos_count: apply_infos 数量（模拟多组场景）
    :param inst_num: 单机多实例上限
    :param clusters_per_apply: 每 apply_info 承载集群数
    :param start_mysql_port: 起始 mysql 端口
    :return: dict
    """
    apply_infos = []
    for i in range(apply_infos_count):
        apply_infos.append(
            {
                "new_ip": {"ip": "3.3.{}.1".format(i), "bk_host_id": 3001 + i * 10, "bk_cloud_id": 0},
                "clusters": [
                    {"master": "grp{}-db{}.example.com".format(i, j), "name": "grp{}_cluster_{}".format(i, j)}
                    for j in range(clusters_per_apply)
                ],
            }
        )
    return {
        "uid": 22222,
        "bk_biz_id": 100,
        "bk_cloud_id": 0,
        "start_mysql_port": start_mysql_port,
        "inst_num": inst_num,
        "apply_infos": apply_infos,
    }


# ---------- Extractor · 正常场景 ----------


def test_extract_single_apply_single_cluster_yields_one_unit():
    """单 apply_info 单集群 -> 1 组 1 unit，端口 = [start_mysql_port]。"""
    ticket = _make_ticket_data(apply_infos_count=1, inst_num=1, clusters_per_apply=1)
    groups = MysqlSingleApplyExtractor().extract(ticket)
    assert len(groups) == 1
    g = groups[0]
    assert g.group_id == "apply_info_0"
    assert len(g.units) == 1

    u = g.units[0]
    assert u.role == ROLE_SINGLE
    assert list(u.expected_ports) == [20000]
    assert u.expected_admin_ports == tuple()  # 需求 1.7：Single 无 proxy 层
    assert list(u.expected_domains) == ["grp0-db0.example.com"]
    assert u.cluster_type == ClusterType.TenDBSingle.value


def test_extract_multi_cluster_multi_instance_ports_cut_by_min():
    """单 apply_info 多集群多实例（inst_num=3, clusters=2）-> 端口按 min 裁剪 = 2 个。"""
    ticket = _make_ticket_data(apply_infos_count=1, inst_num=3, clusters_per_apply=2)
    groups = MysqlSingleApplyExtractor().extract(ticket)
    assert len(groups) == 1
    u = groups[0].units[0]
    # actual_inst_count = min(3, 2) = 2
    assert list(u.expected_ports) == [20000, 20001]
    assert len(u.expected_domains) == 2


def test_extract_inst_num_larger_than_clusters_uses_clusters_length():
    """inst_num=5 但只有 2 个 clusters -> actual_inst_count=2。"""
    ticket = _make_ticket_data(apply_infos_count=1, inst_num=5, clusters_per_apply=2)
    u = MysqlSingleApplyExtractor().extract(ticket)[0].units[0]
    assert list(u.expected_ports) == [20000, 20001]


def test_extract_clusters_larger_than_inst_num_uses_inst_num():
    """inst_num=2 但 clusters=5 -> actual_inst_count=2；域名列表本身仍全部收集。"""
    ticket = _make_ticket_data(apply_infos_count=1, inst_num=2, clusters_per_apply=5)
    u = MysqlSingleApplyExtractor().extract(ticket)[0].units[0]
    assert list(u.expected_ports) == [20000, 20001]
    # expected_domains 保留全部 5 个 master 域名（供后续 DNS 反查使用）
    assert len(u.expected_domains) == 5


def test_extract_multi_apply_info_independent_groups():
    """多 apply_info -> N 组独立、group_id 递增、IP 不重叠（需求 1.3）。"""
    ticket = _make_ticket_data(apply_infos_count=3, inst_num=2, clusters_per_apply=2)
    groups = MysqlSingleApplyExtractor().extract(ticket)
    assert len(groups) == 3
    assert [g.group_id for g in groups] == ["apply_info_0", "apply_info_1", "apply_info_2"]
    # 各组 IP 不重叠
    ips = [g.units[0].ip for g in groups]
    assert len(set(ips)) == 3


def test_extract_cluster_type_and_domains_alignment():
    """断言：cluster_type=TenDBSingle；cluster_domains 与 expected_domains 一致（均等于 clusters[*].master）。"""
    ticket = _make_ticket_data(apply_infos_count=1, inst_num=2, clusters_per_apply=3)
    g = MysqlSingleApplyExtractor().extract(ticket)[0]
    u = g.units[0]
    assert u.cluster_type == ClusterType.TenDBSingle.value
    assert u.expected_domains == g.cluster_domains
    assert list(g.cluster_domains) == [
        "grp0-db0.example.com",
        "grp0-db1.example.com",
        "grp0-db2.example.com",
    ]


# ---------- Extractor · 异常与半合法场景 ----------


def test_extract_missing_apply_infos_returns_empty():
    """ticket_data 缺 apply_infos -> Extractor 返回 []（需求 1.4）。"""
    ticket = {"uid": 1, "bk_biz_id": 100, "start_mysql_port": 20000, "inst_num": 2}
    assert MysqlSingleApplyExtractor().extract(ticket) == []


def test_extract_illegal_ticket_data_type_returns_empty():
    """ticket_data 类型非 dict -> 空列表（需求 1.4）。"""
    assert MysqlSingleApplyExtractor().extract("not a dict") == []
    assert MysqlSingleApplyExtractor().extract(None) == []
    assert MysqlSingleApplyExtractor().extract(123) == []


def test_extract_illegal_field_types_returns_empty():
    """start_mysql_port / inst_num / bk_biz_id 非数字型 -> 返回 []。"""
    ticket = {
        "uid": 1,
        "bk_biz_id": "not-int",
        "start_mysql_port": 20000,
        "inst_num": 2,
        "apply_infos": [],
    }
    assert MysqlSingleApplyExtractor().extract(ticket) == []


def test_extract_apply_infos_empty_list_returns_empty():
    """apply_infos=[] -> 返回 []（合法路径）。"""
    ticket = _make_ticket_data(apply_infos_count=0)
    ticket["apply_infos"] = []
    assert MysqlSingleApplyExtractor().extract(ticket) == []


def test_extract_apply_info_missing_new_ip_skips_that_group():
    """某 apply_info 缺 new_ip -> 跳过该组，其他组正常（需求 1.6）。"""
    ticket = _make_ticket_data(apply_infos_count=2, inst_num=2, clusters_per_apply=2)
    ticket["apply_infos"][0].pop("new_ip")
    groups = MysqlSingleApplyExtractor().extract(ticket)
    assert len(groups) == 1
    assert groups[0].group_id == "apply_info_1"


def test_extract_apply_info_missing_clusters_skips_that_group():
    """某 apply_info 缺 clusters -> 跳过该组，其他组正常（需求 1.6）。"""
    ticket = _make_ticket_data(apply_infos_count=2, inst_num=2, clusters_per_apply=2)
    ticket["apply_infos"][0].pop("clusters")
    groups = MysqlSingleApplyExtractor().extract(ticket)
    assert len(groups) == 1
    assert groups[0].group_id == "apply_info_1"


def test_extract_apply_info_new_ip_missing_bk_host_id_skips_that_group():
    """new_ip 缺 bk_host_id -> 跳过该组。"""
    ticket = _make_ticket_data(apply_infos_count=2, inst_num=2, clusters_per_apply=2)
    ticket["apply_infos"][0]["new_ip"] = {"ip": "3.3.0.1"}  # 缺 bk_host_id
    groups = MysqlSingleApplyExtractor().extract(ticket)
    assert len(groups) == 1
    assert groups[0].group_id == "apply_info_1"


def test_extract_apply_info_new_ip_not_dict_skips_that_group():
    """new_ip 非 dict -> 跳过该组。"""
    ticket = _make_ticket_data(apply_infos_count=2, inst_num=2, clusters_per_apply=2)
    ticket["apply_infos"][0]["new_ip"] = "not-a-dict"
    groups = MysqlSingleApplyExtractor().extract(ticket)
    assert len(groups) == 1
    assert groups[0].group_id == "apply_info_1"


def test_extract_apply_info_non_dict_skips_that_group():
    """apply_info 本身不是 dict -> 跳过该组。"""
    ticket = _make_ticket_data(apply_infos_count=2, inst_num=2, clusters_per_apply=2)
    ticket["apply_infos"][0] = "not-a-dict"
    groups = MysqlSingleApplyExtractor().extract(ticket)
    assert len(groups) == 1
    assert groups[0].group_id == "apply_info_1"
