# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-DB管理系统(BlueKing-BK-DBM) available.
Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

MysqlSingleApplyExtractor + 决策矩阵集成测试。

测试职责：
  - 覆盖需求 3（单机决策矩阵复用）+ 需求 4（组级判据与组结论复用）
  - 覆盖成功标准 1~4：KEEP / RECYCLE / MANUAL / 多组独立场景
  - 断言 GroupDecisionMatrix.classify 在 g2=None（Single 场景 G2 不适用）时的分支覆盖
  - 由于 F 判据涉及 DB / DRSApi 依赖，本文件不做端到端 pipeline mock，
    改用"Extractor → 决策矩阵组合"的纯函数级验证。
"""
from backend.flow.engine.revoke.decision import GroupDecisionMatrix, HostDecisionMatrix
from backend.flow.engine.revoke.extractors.mysql_single_apply import ROLE_SINGLE, MysqlSingleApplyExtractor
from backend.flow.engine.revoke.group_check import ResourceGroupChecker
from backend.flow.engine.revoke.models import FactCheckOutcome, FactState, GroupDecision, HostDecision, HostRevokeFacts


def _make_ticket_data(
    apply_infos_count: int = 1,
    inst_num: int = 2,
    clusters_per_apply: int = 2,
) -> dict:
    """构造合法的 MYSQL_SINGLE_APPLY ticket_data。

    :param apply_infos_count: apply_infos 数量
    :param inst_num: 单机多实例上限
    :param clusters_per_apply: 每 apply_info 承载集群数
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
        "start_mysql_port": 20000,
        "inst_num": inst_num,
        "apply_infos": apply_infos,
    }


def _make_facts(f1: FactState, f2: FactState, f3: FactState, f4: FactState) -> HostRevokeFacts:
    """构造测试用 HostRevokeFacts 快照。"""
    return HostRevokeFacts(
        f1_ownership=FactCheckOutcome(state=f1, reason="F1={}".format(f1.value)),
        f2_traffic=FactCheckOutcome(state=f2, reason="F2={}".format(f2.value)),
        f3_dbm_residue=FactCheckOutcome(state=f3, reason="F3={}".format(f3.value)),
        f4_process=FactCheckOutcome(state=f4, reason="F4={}".format(f4.value)),
    )


def _classify_group_with_same_facts(group, f1, f2, f3, f4):
    """辅助：Single 组内固定 1 台机器，直接跑决策矩阵。G2 传 None（Single 场景不适用）。"""
    verdicts = tuple(HostDecisionMatrix.classify(unit=u, facts=_make_facts(f1, f2, f3, f4)) for u in group.units)
    checker = ResourceGroupChecker(root_id="test-single-root")
    g1 = checker.check_g1_consistency(verdicts)
    return GroupDecisionMatrix.classify(group=group, verdicts=verdicts, g1=g1, g2=None), verdicts, g1


# ---------- 场景 A · KEEP ----------


def test_scenario_a_keep_yields_group_keep():
    """成功标准 1：部署完全成功后终止 → F1=YES F2=YES F3=YES F4=YES → GROUP_KEEP。"""
    ticket = _make_ticket_data(apply_infos_count=1, inst_num=2, clusters_per_apply=2)
    group = MysqlSingleApplyExtractor().extract(ticket)[0]
    gv, verdicts, g1 = _classify_group_with_same_facts(
        group, f1=FactState.YES, f2=FactState.YES, f3=FactState.YES, f4=FactState.YES
    )
    assert verdicts[0].decision == HostDecision.KEEP
    assert g1.state == FactState.YES  # 单元素集合天然一致
    assert gv.decision == GroupDecision.GROUP_KEEP


# ---------- 场景 B · RECYCLE ----------


def test_scenario_b_all_no_yields_group_recycle():
    """成功标准 2：初始化即终止 → F1=YES F2=NO F3=NO F4=NO → GROUP_RECYCLE。"""
    ticket = _make_ticket_data(apply_infos_count=1, inst_num=2, clusters_per_apply=2)
    group = MysqlSingleApplyExtractor().extract(ticket)[0]
    gv, verdicts, _ = _classify_group_with_same_facts(
        group, f1=FactState.YES, f2=FactState.NO, f3=FactState.NO, f4=FactState.NO
    )
    assert verdicts[0].decision == HostDecision.RECYCLE
    # G2 传 None 视作不适用（Single 场景 G2 不适用）→ GROUP_RECYCLE
    assert gv.decision == GroupDecision.GROUP_RECYCLE


def test_scenario_b2_domain_missing_but_process_alive_yields_recycle():
    """F1=YES F2=NO F3=YES F4=YES（域名未绑但进程装完）→ RECYCLE（预期行为，因 F2=NO）。"""
    ticket = _make_ticket_data(apply_infos_count=1, inst_num=1, clusters_per_apply=1)
    group = MysqlSingleApplyExtractor().extract(ticket)[0]
    gv, verdicts, _ = _classify_group_with_same_facts(
        group, f1=FactState.YES, f2=FactState.NO, f3=FactState.YES, f4=FactState.YES
    )
    assert verdicts[0].decision == HostDecision.RECYCLE
    assert gv.decision == GroupDecision.GROUP_RECYCLE


# ---------- 场景 C · MANUAL ----------


def test_scenario_c_domain_bound_but_no_process_yields_manual():
    """成功标准 3：F1=YES F2=YES F4=NO（域名绑了但进程没起来）→ MANUAL → GROUP_MANUAL。"""
    ticket = _make_ticket_data(apply_infos_count=1, inst_num=1, clusters_per_apply=1)
    group = MysqlSingleApplyExtractor().extract(ticket)[0]
    gv, verdicts, _ = _classify_group_with_same_facts(
        group, f1=FactState.YES, f2=FactState.YES, f3=FactState.YES, f4=FactState.NO
    )
    assert verdicts[0].decision == HostDecision.MANUAL
    # 单机 MANUAL + G1=YES 兜底走 GROUP_MANUAL（需求 4.6）
    assert gv.decision == GroupDecision.GROUP_MANUAL


def test_scenario_c2_domain_bound_but_no_meta_yields_manual():
    """F1=YES F2=YES F3=NO F4=YES（域名绑了但 DBM 元数据缺失）→ MANUAL → GROUP_MANUAL。"""
    ticket = _make_ticket_data(apply_infos_count=1, inst_num=1, clusters_per_apply=1)
    group = MysqlSingleApplyExtractor().extract(ticket)[0]
    gv, verdicts, _ = _classify_group_with_same_facts(
        group, f1=FactState.YES, f2=FactState.YES, f3=FactState.NO, f4=FactState.YES
    )
    assert verdicts[0].decision == HostDecision.MANUAL
    assert gv.decision == GroupDecision.GROUP_MANUAL


# ---------- 场景 D · 多组独立 ----------


def test_scenario_d_multi_group_independent_keep_and_recycle():
    """成功标准 4：2 个 apply_info，一组 KEEP、一组 RECYCLE，各自独立处理。"""
    ticket = _make_ticket_data(apply_infos_count=2, inst_num=2, clusters_per_apply=2)
    groups = MysqlSingleApplyExtractor().extract(ticket)
    assert len(groups) == 2

    gv0, _, _ = _classify_group_with_same_facts(
        groups[0], f1=FactState.YES, f2=FactState.YES, f3=FactState.YES, f4=FactState.YES
    )
    gv1, _, _ = _classify_group_with_same_facts(
        groups[1], f1=FactState.YES, f2=FactState.NO, f3=FactState.NO, f4=FactState.NO
    )

    assert gv0.decision == GroupDecision.GROUP_KEEP
    assert gv1.decision == GroupDecision.GROUP_RECYCLE


def test_scenario_d2_multi_group_mixed_keep_and_manual():
    """2 个 apply_info：组 0 KEEP、组 1 MANUAL；组间不互相阻塞（需求 7.5）。"""
    ticket = _make_ticket_data(apply_infos_count=2, inst_num=1, clusters_per_apply=1)
    groups = MysqlSingleApplyExtractor().extract(ticket)

    gv0, _, _ = _classify_group_with_same_facts(
        groups[0], f1=FactState.YES, f2=FactState.YES, f3=FactState.YES, f4=FactState.YES
    )
    gv1, _, _ = _classify_group_with_same_facts(
        groups[1], f1=FactState.YES, f2=FactState.YES, f3=FactState.NO, f4=FactState.YES
    )

    assert gv0.decision == GroupDecision.GROUP_KEEP
    assert gv1.decision == GroupDecision.GROUP_MANUAL


# ---------- 场景 E · SKIP ----------


def test_scenario_e_f1_no_yields_group_skip():
    """F1=NO（机器已不属于本单据）→ SKIP → GROUP_SKIP。"""
    ticket = _make_ticket_data(apply_infos_count=1, inst_num=1, clusters_per_apply=1)
    group = MysqlSingleApplyExtractor().extract(ticket)[0]
    gv, verdicts, _ = _classify_group_with_same_facts(
        group, f1=FactState.NO, f2=FactState.NO, f3=FactState.NO, f4=FactState.NO
    )
    assert verdicts[0].decision == HostDecision.SKIP
    assert gv.decision == GroupDecision.GROUP_SKIP


def test_scenario_e2_f1_unknown_yields_group_skip():
    """F1=UNKNOWN → SKIP（数据源不可达时保守跳过，不进入清理）→ GROUP_SKIP。"""
    ticket = _make_ticket_data(apply_infos_count=1, inst_num=1, clusters_per_apply=1)
    group = MysqlSingleApplyExtractor().extract(ticket)[0]
    gv, verdicts, _ = _classify_group_with_same_facts(
        group, f1=FactState.UNKNOWN, f2=FactState.NO, f3=FactState.NO, f4=FactState.NO
    )
    assert verdicts[0].decision == HostDecision.SKIP
    assert gv.decision == GroupDecision.GROUP_SKIP


# ---------- 单元契约断言 · role=single 场景专属特性 ----------


def test_single_unit_role_is_single_and_no_admin_ports():
    """Single 场景单元契约：role="single"、expected_admin_ports 为空 tuple、expected_domains 仅含 master 域名。"""
    ticket = _make_ticket_data(apply_infos_count=1, inst_num=2, clusters_per_apply=3)
    group = MysqlSingleApplyExtractor().extract(ticket)[0]
    u = group.units[0]
    assert u.role == ROLE_SINGLE
    assert u.expected_admin_ports == tuple()
    # 与 cluster_domains 对齐（Single 只绑主域名）
    assert u.expected_domains == group.cluster_domains


def test_single_group_g2_returns_none_for_no_proxy():
    """Single 组无 proxy → check_g2_architecture 触发条件不满足 → 返回 None。"""
    ticket = _make_ticket_data(apply_infos_count=1, inst_num=1, clusters_per_apply=1)
    group = MysqlSingleApplyExtractor().extract(ticket)[0]
    # 组内所有单机结论都为 RECYCLE + F4=YES 时，check_g2_architecture 才会去访问 proxy
    # Single 场景 get_proxy_units() 返回空 → 直接返回 None（不适用）
    verdicts = tuple(
        HostDecisionMatrix.classify(
            unit=u,
            facts=_make_facts(FactState.YES, FactState.NO, FactState.YES, FactState.YES),
        )
        for u in group.units
    )
    checker = ResourceGroupChecker(root_id="test-single-root")
    g2 = checker.check_g2_architecture(group=group, verdicts=verdicts)
    assert g2 is None
