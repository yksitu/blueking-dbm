# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-DB管理系统(BlueKing-BK-DBM) available.
Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

MysqlHaApplyExtractor 与顶层 revoke_flow 集成测试。

测试职责：
  - 覆盖需求文档"成功标准"第 4 项：多组 apply_info 独立处理（Extractor 层）
  - 覆盖 ticket_data 结构合法/缺失/半合法场景的 Extractor 输出契约
  - 由于 F 判据涉及 DB / DRSApi 依赖，本文件不做端到端 pipeline mock，
    改用"Extractor → 决策矩阵组合"的纯函数级验证覆盖成功标准 1~3。
    完整的 bamboo pipeline 集成留待联调环境跑 shell_verify_host_check.py。
"""
from backend.flow.engine.revoke.decision import GroupDecisionMatrix, HostDecisionMatrix
from backend.flow.engine.revoke.extractors.mysql_ha_apply import (
    ROLE_BACKEND_MASTER,
    ROLE_BACKEND_SLAVE,
    ROLE_PROXY,
    MysqlHaApplyExtractor,
)
from backend.flow.engine.revoke.group_check import ResourceGroupChecker
from backend.flow.engine.revoke.models import FactCheckOutcome, FactState, GroupDecision, HostRevokeFacts


def _make_ticket_data(
    apply_infos_count: int = 1,
    inst_num: int = 2,
    clusters_per_apply: int = 3,
) -> dict:
    """构造合法的 MYSQL_HA_APPLY ticket_data。

    :param apply_infos_count: apply_infos 数量（模拟多组场景）
    :param inst_num: 单机多实例数
    :param clusters_per_apply: 每 apply_info 承载集群数
    :return: dict
    """
    apply_infos = []
    for i in range(apply_infos_count):
        apply_infos.append(
            {
                "proxy_ip_list": [
                    {"ip": "1.1.{}.1".format(i), "bk_host_id": 1001 + i * 10, "bk_cloud_id": 0},
                    {"ip": "1.1.{}.2".format(i), "bk_host_id": 1002 + i * 10, "bk_cloud_id": 0},
                ],
                "mysql_ip_list": [
                    {"ip": "2.2.{}.1".format(i), "bk_host_id": 2001 + i * 10, "bk_cloud_id": 0},
                    {"ip": "2.2.{}.2".format(i), "bk_host_id": 2002 + i * 10, "bk_cloud_id": 0},
                ],
                "clusters": [
                    {
                        "master": "grp{}-db{}.example.com".format(i, j),
                        "slave": "grp{}-dr{}.example.com".format(i, j),
                        "name": "grp{}_cluster_{}".format(i, j),
                    }
                    for j in range(clusters_per_apply)
                ],
            }
        )
    return {
        "uid": 12345,
        "bk_biz_id": 100,
        "bk_cloud_id": 0,
        "start_proxy_port": 10000,
        "start_mysql_port": 20000,
        "inst_num": inst_num,
        "apply_infos": apply_infos,
    }


# ---------- Extractor · 正常与异常 ticket_data ----------


def test_extract_single_apply_info_yields_one_group():
    """单组 apply_info -> 1 个 ResourceGroup，含 2 proxy + 1 master + 1 slave = 4 units。"""
    ticket = _make_ticket_data(apply_infos_count=1, inst_num=2, clusters_per_apply=3)
    groups = MysqlHaApplyExtractor().extract(ticket)
    assert len(groups) == 1
    g = groups[0]
    assert g.group_id == "apply_info_0"
    assert len(g.units) == 4
    # 角色分布
    roles = [u.role for u in g.units]
    assert roles.count(ROLE_PROXY) == 2
    assert roles.count(ROLE_BACKEND_MASTER) == 1
    assert roles.count(ROLE_BACKEND_SLAVE) == 1
    # backend_master 不绑域名，backend_slave 绑 slave 域名
    master_units = g.get_master_units()
    slave_units = [u for u in g.units if u.role == ROLE_BACKEND_SLAVE]
    assert master_units[0].expected_domains == tuple()
    assert len(slave_units[0].expected_domains) == 3


def test_extract_multi_apply_info_independent_groups():
    """多组 apply_info -> N 个独立 ResourceGroup，group_id 递增。"""
    ticket = _make_ticket_data(apply_infos_count=3, inst_num=2, clusters_per_apply=2)
    groups = MysqlHaApplyExtractor().extract(ticket)
    assert len(groups) == 3
    assert [g.group_id for g in groups] == ["apply_info_0", "apply_info_1", "apply_info_2"]
    # 各组机器 IP 不重叠
    all_ips = set()
    for g in groups:
        group_ips = {u.ip for u in g.units}
        assert not (all_ips & group_ips), "组间 IP 不应重叠"
        all_ips |= group_ips


def test_extract_ports_follow_min_inst_num_and_clusters():
    """端口计算：actual_inst_count = min(inst_num, len(clusters))。"""
    # inst_num=5 但 clusters 只有 2 → 端口数 = 2
    ticket = _make_ticket_data(apply_infos_count=1, inst_num=5, clusters_per_apply=2)
    g = MysqlHaApplyExtractor().extract(ticket)[0]
    proxy_unit = g.get_units_by_role(ROLE_PROXY)[0]
    assert list(proxy_unit.expected_ports) == [10000, 10001]
    assert list(proxy_unit.expected_admin_ports) == [11000, 11001]
    master_unit = g.get_master_units()[0]
    assert list(master_unit.expected_ports) == [20000, 20001]


def test_extract_missing_apply_infos_returns_empty():
    """ticket_data 缺 apply_infos -> Extractor 返回 []（不抛异常）。"""
    ticket = {"uid": 1, "bk_biz_id": 100, "start_proxy_port": 10000, "start_mysql_port": 20000, "inst_num": 2}
    assert MysqlHaApplyExtractor().extract(ticket) == []


def test_extract_illegal_ticket_data_type_returns_empty():
    """ticket_data 类型非 dict -> 空列表。"""
    assert MysqlHaApplyExtractor().extract("not a dict") == []
    assert MysqlHaApplyExtractor().extract(None) == []


def test_extract_partial_missing_apply_info_skips_that_group():
    """某 apply_info 字段不合法 -> 跳过该组，其他组正常处理。"""
    ticket = _make_ticket_data(apply_infos_count=2, inst_num=2, clusters_per_apply=2)
    # 第 0 组 mysql_ip_list 长度不足 2 → 跳过
    ticket["apply_infos"][0]["mysql_ip_list"] = ticket["apply_infos"][0]["mysql_ip_list"][:1]
    groups = MysqlHaApplyExtractor().extract(ticket)
    # 只留下第 1 组
    assert len(groups) == 1
    assert groups[0].group_id == "apply_info_1"


# ---------- 集成场景 · Extractor + 决策矩阵 组合 ----------


def _make_facts(f1: FactState, f2: FactState, f3: FactState, f4: FactState) -> HostRevokeFacts:
    """构造测试用 HostRevokeFacts 快照。"""
    return HostRevokeFacts(
        f1_ownership=FactCheckOutcome(state=f1, reason="F1={}".format(f1.value)),
        f2_traffic=FactCheckOutcome(state=f2, reason="F2={}".format(f2.value)),
        f3_dbm_residue=FactCheckOutcome(state=f3, reason="F3={}".format(f3.value)),
        f4_process=FactCheckOutcome(state=f4, reason="F4={}".format(f4.value)),
    )


def _classify_all_units_with_same_facts(group, f1, f2, f3, f4):
    """辅助：把组内所有 units 的 F 判据都设成相同状态，跑 HostDecisionMatrix + GroupDecisionMatrix。"""
    verdicts = tuple(HostDecisionMatrix.classify(unit=u, facts=_make_facts(f1, f2, f3, f4)) for u in group.units)
    checker = ResourceGroupChecker(root_id="test-root")
    g1 = checker.check_g1_consistency(verdicts)
    # G2 场景与本测试无关（不发 RPC，直接 None）
    return GroupDecisionMatrix.classify(group=group, verdicts=verdicts, g1=g1, g2=None)


def test_scenario_a_all_keep_yields_group_keep():
    """成功标准 1：部署完全成功后终止 → 全组 F 全 YES → GROUP_KEEP。"""
    ticket = _make_ticket_data(apply_infos_count=1)
    group = MysqlHaApplyExtractor().extract(ticket)[0]
    gv = _classify_all_units_with_same_facts(
        group, f1=FactState.YES, f2=FactState.YES, f3=FactState.YES, f4=FactState.YES
    )
    assert gv.decision == GroupDecision.GROUP_KEEP


def test_scenario_b_all_recycle_yields_group_recycle():
    """成功标准 2：初始化即终止 → 全组 F1=YES F2=NO F3=NO F4=NO → GROUP_RECYCLE。"""
    ticket = _make_ticket_data(apply_infos_count=1)
    group = MysqlHaApplyExtractor().extract(ticket)[0]
    gv = _classify_all_units_with_same_facts(
        group, f1=FactState.YES, f2=FactState.NO, f3=FactState.NO, f4=FactState.NO
    )
    # G2 传 None 视作不适用 → GROUP_RECYCLE
    assert gv.decision == GroupDecision.GROUP_RECYCLE


def test_scenario_c_mixed_yields_group_manual():
    """成功标准 3：proxy 装完但 backend 未装 → G1 混合结论 → GROUP_MANUAL。

    模拟：proxy 全 KEEP、backend 全 RECYCLE，得到 G1 混合。
    """
    ticket = _make_ticket_data(apply_infos_count=1)
    group = MysqlHaApplyExtractor().extract(ticket)[0]
    verdicts_list = []
    for u in group.units:
        if u.role == ROLE_PROXY:
            facts = _make_facts(FactState.YES, FactState.YES, FactState.YES, FactState.YES)  # KEEP
        else:
            facts = _make_facts(FactState.YES, FactState.NO, FactState.NO, FactState.NO)  # RECYCLE
        verdicts_list.append(HostDecisionMatrix.classify(unit=u, facts=facts))
    verdicts = tuple(verdicts_list)

    checker = ResourceGroupChecker(root_id="test-root")
    g1 = checker.check_g1_consistency(verdicts)
    gv = GroupDecisionMatrix.classify(group=group, verdicts=verdicts, g1=g1, g2=None)
    assert gv.decision == GroupDecision.GROUP_MANUAL


def test_scenario_d_multi_group_independent():
    """成功标准 4：多组混合，组间独立处理。组 0 全 KEEP、组 1 全 RECYCLE。"""
    ticket = _make_ticket_data(apply_infos_count=2, inst_num=2, clusters_per_apply=2)
    groups = MysqlHaApplyExtractor().extract(ticket)
    assert len(groups) == 2

    gv0 = _classify_all_units_with_same_facts(
        groups[0], f1=FactState.YES, f2=FactState.YES, f3=FactState.YES, f4=FactState.YES
    )
    gv1 = _classify_all_units_with_same_facts(
        groups[1], f1=FactState.YES, f2=FactState.NO, f3=FactState.NO, f4=FactState.NO
    )

    # 组间独立：组 0 KEEP、组 1 RECYCLE
    assert gv0.decision == GroupDecision.GROUP_KEEP
    assert gv1.decision == GroupDecision.GROUP_RECYCLE


def test_scenario_all_skip_yields_group_skip():
    """全组 F1=NO → 全 SKIP → GROUP_SKIP（机器已不属于本单据）。"""
    ticket = _make_ticket_data(apply_infos_count=1)
    group = MysqlHaApplyExtractor().extract(ticket)[0]
    gv = _classify_all_units_with_same_facts(group, f1=FactState.NO, f2=FactState.NO, f3=FactState.NO, f4=FactState.NO)
    assert gv.decision == GroupDecision.GROUP_SKIP
