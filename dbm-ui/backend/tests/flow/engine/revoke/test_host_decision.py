# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-DB管理系统(BlueKing-BK-DBM) available.
Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

HostDecisionMatrix 单元测试。

测试职责：
  - 覆盖需求文档"组决策判断表 · 表 2"的全部 11 行 F1~F4 组合
  - 覆盖 F2 UNKNOWN / F3 UNKNOWN / F4 UNKNOWN 的额外保守挂起分支
  - 确保决策函数为纯函数（相同输入相同输出、无副作用）
"""
import pytest

from backend.flow.engine.revoke.decision import HostDecisionMatrix
from backend.flow.engine.revoke.models import FactCheckOutcome, FactState, HostDecision, HostRevokeFacts, RevokeUnit


def _make_unit(role: str = "proxy") -> RevokeUnit:
    """构造测试用 RevokeUnit（避免 fixture 冗余）。

    :param role: 角色字符串
    :return: 一个合法的 RevokeUnit 实例
    """
    return RevokeUnit(
        ip="1.2.3.4",
        bk_host_id=101,
        bk_cloud_id=0,
        bk_biz_id=100,
        role=role,
        expected_ports=(10000,),
    )


def _make_facts(f1: FactState, f2: FactState, f3: FactState, f4: FactState) -> HostRevokeFacts:
    """构造测试用 HostRevokeFacts 快照。

    :param f1: F1 state
    :param f2: F2 state
    :param f3: F3 state
    :param f4: F4 state
    :return: HostRevokeFacts 实例
    """
    return HostRevokeFacts(
        f1_ownership=FactCheckOutcome(state=f1, reason="F1={}".format(f1.value)),
        f2_traffic=FactCheckOutcome(state=f2, reason="F2={}".format(f2.value)),
        f3_dbm_residue=FactCheckOutcome(state=f3, reason="F3={}".format(f3.value)),
        f4_process=FactCheckOutcome(state=f4, reason="F4={}".format(f4.value)),
    )


# ---------- 表 2 · 11 行 F 组合覆盖 ----------


@pytest.mark.parametrize(
    "f1,f2,f3,f4,expected",
    [
        # 表 2 第 1 行：F1=NO → SKIP（* 用 YES 代表）
        (FactState.NO, FactState.YES, FactState.YES, FactState.YES, HostDecision.SKIP),
        # 表 2 第 1 行变体：F1=UNKNOWN → SKIP
        (FactState.UNKNOWN, FactState.YES, FactState.YES, FactState.YES, HostDecision.SKIP),
        # 表 2 第 2 行：F1=YES F2=YES F3=YES F4=YES → KEEP
        (FactState.YES, FactState.YES, FactState.YES, FactState.YES, HostDecision.KEEP),
        # 表 2 第 3 行：F1=YES F2=YES F3=NO F4=YES → MANUAL
        (FactState.YES, FactState.YES, FactState.NO, FactState.YES, HostDecision.MANUAL),
        # 表 2 第 3 行变体：F3=NO F4=NO
        (FactState.YES, FactState.YES, FactState.NO, FactState.NO, HostDecision.MANUAL),
        # 表 2 第 4 行：F1=YES F2=YES F3=YES F4=NO → MANUAL
        (FactState.YES, FactState.YES, FactState.YES, FactState.NO, HostDecision.MANUAL),
        # 表 2 第 5 行：F1=YES F2=YES F4=UNKNOWN → MANUAL
        (FactState.YES, FactState.YES, FactState.YES, FactState.UNKNOWN, HostDecision.MANUAL),
        # 表 2 第 6 行：F1=YES F2=UNKNOWN → MANUAL
        (FactState.YES, FactState.UNKNOWN, FactState.YES, FactState.YES, HostDecision.MANUAL),
        (FactState.YES, FactState.UNKNOWN, FactState.NO, FactState.NO, HostDecision.MANUAL),
        # 表 2 第 7 行：F1=YES F2=NO F4=UNKNOWN → MANUAL
        (FactState.YES, FactState.NO, FactState.YES, FactState.UNKNOWN, HostDecision.MANUAL),
        (FactState.YES, FactState.NO, FactState.NO, FactState.UNKNOWN, HostDecision.MANUAL),
        # 表 2 第 8 行：F1=YES F2=NO F3=NO F4=NO → RECYCLE
        (FactState.YES, FactState.NO, FactState.NO, FactState.NO, HostDecision.RECYCLE),
        # 表 2 第 9 行：F1=YES F2=NO F3=NO F4=YES → RECYCLE
        (FactState.YES, FactState.NO, FactState.NO, FactState.YES, HostDecision.RECYCLE),
        # 表 2 第 10 行：F1=YES F2=NO F3=YES F4=NO → RECYCLE
        (FactState.YES, FactState.NO, FactState.YES, FactState.NO, HostDecision.RECYCLE),
        # 表 2 第 11 行：F1=YES F2=NO F3=YES F4=YES → RECYCLE
        (FactState.YES, FactState.NO, FactState.YES, FactState.YES, HostDecision.RECYCLE),
    ],
)
def test_host_decision_matrix_table2(f1, f2, f3, f4, expected):
    """遍历表 2 全部 F 组合，验证 HostDecisionMatrix.classify 产出与需求文档一致。"""
    unit = _make_unit(role="proxy")
    facts = _make_facts(f1, f2, f3, f4)
    verdict = HostDecisionMatrix.classify(unit, facts)
    assert verdict.decision == expected, "F1={} F2={} F3={} F4={} expected={}, got={}".format(
        f1, f2, f3, f4, expected, verdict.decision
    )
    # 决策必附带非空 reason
    assert verdict.reason
    # 引用透传
    assert verdict.unit is unit
    assert verdict.facts is facts


# ---------- 决策纯函数属性 ----------


def test_host_decision_is_pure_function():
    """同一输入多次调用得到相同结果，且不修改入参对象。"""
    unit = _make_unit(role="backend_master")
    facts = _make_facts(FactState.YES, FactState.NO, FactState.YES, FactState.YES)
    v1 = HostDecisionMatrix.classify(unit, facts)
    v2 = HostDecisionMatrix.classify(unit, facts)
    assert v1.decision == v2.decision
    assert v1.reason == v2.reason
    # 入参对象未被修改
    assert facts.f1_ownership.state == FactState.YES


# ---------- 关键短路顺序 ----------


def test_f1_no_short_circuits_regardless_of_other_facts():
    """F1=NO 时应直接 SKIP，不受 F2/F3/F4 影响。"""
    unit = _make_unit()
    for f2 in FactState:
        for f3 in FactState:
            for f4 in FactState:
                facts = _make_facts(FactState.NO, f2, f3, f4)
                assert HostDecisionMatrix.classify(unit, facts).decision == HostDecision.SKIP


def test_f2_unknown_forces_manual_when_f1_yes():
    """F1=YES 时，F2=UNKNOWN 无论 F3/F4 如何都应 MANUAL。"""
    unit = _make_unit()
    for f3 in FactState:
        for f4 in FactState:
            facts = _make_facts(FactState.YES, FactState.UNKNOWN, f3, f4)
            assert HostDecisionMatrix.classify(unit, facts).decision == HostDecision.MANUAL
