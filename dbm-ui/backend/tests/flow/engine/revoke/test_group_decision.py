# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-DB管理系统(BlueKing-BK-DBM) available.
Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

GroupDecisionMatrix 与 ResourceGroupChecker.check_g1_consistency 单元测试。

测试职责：
  - 覆盖需求文档"组决策判断表 · 表 4"的 8 行组合
  - 覆盖 G2 UNKNOWN 时的保守挂起分支
  - 覆盖 G1 判据在各种组内一致性场景下的产出
"""
from backend.flow.engine.revoke.decision import GroupDecisionMatrix
from backend.flow.engine.revoke.group_check import ResourceGroupChecker
from backend.flow.engine.revoke.models import (
    FactCheckOutcome,
    FactState,
    GroupDecision,
    HostDecision,
    HostRevokeFacts,
    ResourceGroup,
    RevokeUnit,
    RevokeVerdict,
)


def _make_unit(ip: str, role: str = "proxy") -> RevokeUnit:
    """构造测试用 RevokeUnit。"""
    return RevokeUnit(
        ip=ip,
        bk_host_id=abs(hash(ip)) % 10**8,
        bk_cloud_id=0,
        bk_biz_id=100,
        role=role,
        expected_ports=(10000,),
    )


def _make_facts_all_yes() -> HostRevokeFacts:
    """构造 F1~F4 全 YES 的 facts（对应 KEEP 决策）。"""
    return HostRevokeFacts(
        f1_ownership=FactCheckOutcome(state=FactState.YES, reason="F1=YES"),
        f2_traffic=FactCheckOutcome(state=FactState.YES, reason="F2=YES"),
        f3_dbm_residue=FactCheckOutcome(state=FactState.YES, reason="F3=YES"),
        f4_process=FactCheckOutcome(state=FactState.YES, reason="F4=YES"),
    )


def _make_verdict(ip: str, decision: HostDecision, role: str = "proxy") -> RevokeVerdict:
    """构造指定 decision 的 RevokeVerdict（facts 全 YES 只是占位，不参与组决策）。"""
    return RevokeVerdict(
        unit=_make_unit(ip, role=role),
        decision=decision,
        facts=_make_facts_all_yes(),
        reason="test verdict decision={}".format(decision.value),
    )


def _make_group(ips: list) -> ResourceGroup:
    """构造包含 N 台机器的 ResourceGroup。"""
    units = tuple(_make_unit(ip) for ip in ips)
    return ResourceGroup(group_id="test_grp", units=units, cluster_domains=("test.example.com",))


# ---------- G1 判据 ----------


def test_g1_all_same_decision_yields_yes():
    """组内所有单机结论一致 → G1=YES。"""
    verdicts = tuple(_make_verdict("1.1.1.{}".format(i), HostDecision.RECYCLE) for i in range(1, 4))
    outcome = ResourceGroupChecker(root_id="root-x").check_g1_consistency(verdicts)
    assert outcome.state == FactState.YES


def test_g1_mixed_decisions_yields_no():
    """组内出现不同单机结论 → G1=NO。"""
    verdicts = (
        _make_verdict("1.1.1.1", HostDecision.RECYCLE),
        _make_verdict("1.1.1.2", HostDecision.KEEP),
    )
    outcome = ResourceGroupChecker(root_id="root-x").check_g1_consistency(verdicts)
    assert outcome.state == FactState.NO


def test_g1_empty_verdicts_yields_unknown():
    """组内无 verdict → G1=UNKNOWN。"""
    outcome = ResourceGroupChecker(root_id="root-x").check_g1_consistency(tuple())
    assert outcome.state == FactState.UNKNOWN


# ---------- 表 4 · 8 行组决策覆盖 ----------


def _run_matrix(
    decisions: list,
    g1_state: FactState,
    g2_state=None,
) -> GroupDecision:
    """辅助：给定组内单机 decisions 与 G1/G2 状态，返回组决策。"""
    ips = ["10.0.0.{}".format(i) for i in range(len(decisions))]
    verdicts = tuple(_make_verdict(ip, d) for ip, d in zip(ips, decisions))
    group = _make_group(ips)
    g1 = FactCheckOutcome(state=g1_state, reason="g1")
    g2 = FactCheckOutcome(state=g2_state, reason="g2") if g2_state is not None else None
    gv = GroupDecisionMatrix.classify(group=group, verdicts=verdicts, g1=g1, g2=g2)
    return gv.decision


def test_table4_row1_all_skip_yields_group_skip():
    """表 4 第 1 行：全部 SKIP + G1=YES → GROUP_SKIP。"""
    assert _run_matrix([HostDecision.SKIP, HostDecision.SKIP], g1_state=FactState.YES) == GroupDecision.GROUP_SKIP


def test_table4_row2_all_keep_yields_group_keep():
    """表 4 第 2 行：全部 KEEP + G1=YES → GROUP_KEEP。"""
    assert _run_matrix([HostDecision.KEEP, HostDecision.KEEP], g1_state=FactState.YES) == GroupDecision.GROUP_KEEP


def test_table4_row3_all_recycle_g2_yes_yields_group_recycle():
    """表 4 第 3 行：全部 RECYCLE + G1=YES + G2=YES → GROUP_RECYCLE。"""
    assert (
        _run_matrix(
            [HostDecision.RECYCLE, HostDecision.RECYCLE],
            g1_state=FactState.YES,
            g2_state=FactState.YES,
        )
        == GroupDecision.GROUP_RECYCLE
    )


def test_table4_row3_variant_all_recycle_g2_none_yields_group_recycle():
    """表 4 第 3 行变体：全部 RECYCLE + G1=YES + G2 不适用（None）→ GROUP_RECYCLE。"""
    assert (
        _run_matrix([HostDecision.RECYCLE, HostDecision.RECYCLE], g1_state=FactState.YES, g2_state=None)
        == GroupDecision.GROUP_RECYCLE
    )


def test_table4_row4_all_recycle_g2_no_yields_group_manual():
    """表 4 第 4 行：全部 RECYCLE + G1=YES + G2=NO → GROUP_MANUAL。"""
    assert (
        _run_matrix(
            [HostDecision.RECYCLE, HostDecision.RECYCLE],
            g1_state=FactState.YES,
            g2_state=FactState.NO,
        )
        == GroupDecision.GROUP_MANUAL
    )


def test_table4_row4_variant_g2_unknown_yields_group_manual():
    """G2=UNKNOWN 也应保守挂起 → GROUP_MANUAL。"""
    assert (
        _run_matrix(
            [HostDecision.RECYCLE, HostDecision.RECYCLE],
            g1_state=FactState.YES,
            g2_state=FactState.UNKNOWN,
        )
        == GroupDecision.GROUP_MANUAL
    )


def test_table4_row5_contains_manual_yields_group_manual():
    """表 4 第 5 行：组内出现 MANUAL → GROUP_MANUAL。"""
    assert (
        _run_matrix([HostDecision.RECYCLE, HostDecision.MANUAL], g1_state=FactState.NO) == GroupDecision.GROUP_MANUAL
    )


def test_table4_row6_recycle_keep_mix_yields_group_manual():
    """表 4 第 6 行：RECYCLE + KEEP 混合 → GROUP_MANUAL。"""
    assert _run_matrix([HostDecision.RECYCLE, HostDecision.KEEP], g1_state=FactState.NO) == GroupDecision.GROUP_MANUAL


def test_table4_row7_recycle_skip_mix_yields_group_manual():
    """表 4 第 7 行：RECYCLE + SKIP 混合 → GROUP_MANUAL。"""
    assert _run_matrix([HostDecision.RECYCLE, HostDecision.SKIP], g1_state=FactState.NO) == GroupDecision.GROUP_MANUAL


def test_table4_row8_keep_skip_mix_yields_group_manual():
    """表 4 第 8 行：KEEP + SKIP 混合 → GROUP_MANUAL。"""
    assert _run_matrix([HostDecision.KEEP, HostDecision.SKIP], g1_state=FactState.NO) == GroupDecision.GROUP_MANUAL


# ---------- 组决策纯函数属性 ----------


def test_group_decision_stable_output():
    """同一输入多次调用产出一致的决策。"""
    ips = ["1.2.3.1", "1.2.3.2"]
    verdicts = tuple(_make_verdict(ip, HostDecision.RECYCLE) for ip in ips)
    group = _make_group(ips)
    g1 = FactCheckOutcome(state=FactState.YES, reason="ok")
    g2 = FactCheckOutcome(state=FactState.YES, reason="ok")
    d1 = GroupDecisionMatrix.classify(group=group, verdicts=verdicts, g1=g1, g2=g2).decision
    d2 = GroupDecisionMatrix.classify(group=group, verdicts=verdicts, g1=g1, g2=g2).decision
    assert d1 == d2 == GroupDecision.GROUP_RECYCLE
