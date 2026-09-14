# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-DB管理系统(BlueKing-BK-DBM) available.
Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

HostRevokeChecker Django shell 手动验证脚本。

用途：
  在开发/联调环境用真实 DB + 真实外部服务，直接观察 4 个判定方法的输出。
  不做数据插桩、不写 mock，仅**只读**验证。

使用方式：
  1) 进入项目根目录：`cd /data/github/blueking-dbm/dbm-ui`
  2) 启动 shell：`python manage.py shell`
  3) 粘贴 verify_all() 或 verify_one_by_one() 的调用示例（见文件末尾"用法示例"）

依赖前置：
  - 需要一台**在 DBM 数据库中已有记录**的真实机器（bk_host_id / ip / bk_cloud_id / bk_biz_id）
  - 需要一个**真实存在的单据 ticket_id**（不必与该机器强关联；不匹配时正好验证 TICKET_MISMATCH 分支）
  - CLB / DNS / CC 接口在当前环境可达（否则会走 CHECK_ERROR 分支）

边界：
  - 本脚本**只读**：不会 create / update / delete 任何 DB 记录，不会调 CLB / DNS 的变更类 API
  - 打印格式：每个方法一行 header + 结构化 JSON dump 结果
"""
import json
import logging
import sys
from typing import Any, Dict, List, Optional

from backend.flow.engine.revoke.host_check import HostCheckResult, HostRevokeChecker
from backend.ticket.models import Ticket


def _dump(label: str, obj: Any) -> None:
    """结构化打印工具：把 HostCheckResult 或 dict 转成 JSON 输出。

    :param label: 输出前缀标签，例如 "check_dns_mapping"
    :param obj: 要打印的对象（支持 HostCheckResult / dict / 其他）
    :return: None
    边界：
      - obj 为 HostCheckResult -> 拆解为 dict 打印
      - obj 含 datetime / 其他不可序列化对象 -> 走 default=str 兜底
    """
    print("\n" + "=" * 80)
    print("[{label}]".format(label=label))
    print("-" * 80)

    if isinstance(obj, HostCheckResult):
        payload: Dict[str, Any] = {
            "passed": obj.passed,
            "reason_code": obj.reason_code,
            "reason": obj.reason,
            "evidence": obj.evidence,
        }
    else:
        payload = obj

    try:
        print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    except Exception as err:  # 万一 json 处理失败，直接 repr 兜底
        print("json dump failed: {}, fallback repr:".format(err))
        print(repr(payload))


def _build_checker(
    ticket_id: int,
    bk_biz_id: int,
    bk_cloud_id: int,
    ip: str,
    bk_host_id: int,
    root_id: str = "shell-verify-001",
) -> HostRevokeChecker:
    """构造 HostRevokeChecker 实例。

    :param ticket_id: 真实存在的单据 id
    :param bk_biz_id: 业务 id
    :param bk_cloud_id: 云区域 id（0 = 直连）
    :param ip: 主机 IP
    :param bk_host_id: 主机 id
    :param root_id: 日志标识，默认 shell-verify-001
    :return: HostRevokeChecker 实例
    边界：
      - ticket_id 不存在 -> raise Ticket.DoesNotExist
      - 其他入参校验失败 -> raise RevokeFlowBaseException（由构造器校验）
    """
    ticket = Ticket.objects.get(id=ticket_id)
    return HostRevokeChecker(
        root_id=root_id,
        ticket=ticket,
        bk_biz_id=bk_biz_id,
        bk_cloud_id=bk_cloud_id,
        ip=ip,
        bk_host_id=bk_host_id,
    )


def _enable_debug_log() -> None:
    """把 flow logger 提升到 INFO 级别，方便看到 HostRevokeChecker 输出的日志行。

    :return: None
    边界：
      - 若 shell 环境本身已配置更详细级别，不覆盖
    """
    lg = logging.getLogger("flow")
    if lg.level == logging.NOTSET or lg.level > logging.INFO:
        lg.setLevel(logging.INFO)
    # 避免没有 handler 时日志沉默
    if not lg.handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        lg.addHandler(h)


# ------------------------------------------------------------
# 4 个方法逐项验证入口（可以单个跑，也可以整体跑）
# ------------------------------------------------------------


def verify_check_in_ticket_scope(checker: HostRevokeChecker) -> HostCheckResult:
    """验证需求 2：check_in_ticket_scope。

    预期观察：
      - 若该机器没有任何 MachineEvent -> reason_code=no_machine_event
      - 若最近事件 ticket_id 与 checker.ticket.id 不同 -> reason_code=ticket_mismatch
      - 若 CC 查不到该主机 -> reason_code=cc_host_not_found
      - 若 bk_module_id 与资源池模块不一致 -> reason_code=module_mismatch
      - 全部通过 -> reason_code=ok
    """
    r = checker.check_in_ticket_scope()
    _dump("check_in_ticket_scope", r)
    return r


def verify_check_clb_mapping(checker: HostRevokeChecker, regions: List[str]) -> HostCheckResult:
    """验证需求 3：check_clb_mapping。

    :param regions: CLB region 列表，例如 ["南京", "上海"]；不知道就传 ["南京"] 试一次
    预期观察：
      - regions=[] -> reason_code=no_region_input
      - IP 在 CLB 后端注册 -> reason_code=ip_registered_in_clb（passed=False）
      - 未注册 -> reason_code=ip_not_registered_in_clb（passed=True）
      - 部分 region 异常但未命中 -> reason_code=check_error
    """
    r = checker.check_clb_mapping(regions=regions)
    _dump("check_clb_mapping regions={}".format(regions), r)
    return r


def verify_check_dns_mapping(checker: HostRevokeChecker) -> HostCheckResult:
    """验证需求 4：check_dns_mapping。

    预期观察：
      - DNS 服务返回 detail=[] -> reason_code=ip_no_dns_record（passed=True）
      - detail 非空 -> reason_code=ip_has_dns_record（passed=False），evidence.records 列出域名
      - DnsApi 抛异常或返回结构异常 -> reason_code=check_error
    """
    r = checker.check_dns_mapping()
    _dump("check_dns_mapping", r)
    return r


def verify_check_dbm_metadata(checker: HostRevokeChecker) -> HostCheckResult:
    """验证需求 5：check_dbm_metadata。

    预期观察：
      - Machine 不存在 -> reason_code=no_machine
      - Machine 存在但无 Instance -> reason_code=no_instance
      - Instance port=0/None -> reason_code=instance_port_invalid
      - Instance 未绑定 Cluster -> reason_code=instance_no_cluster
      - 全通过 -> reason_code=ok，evidence 记录 instance_count / cluster_ids
    """
    r = checker.check_dbm_metadata()
    _dump("check_dbm_metadata", r)
    return r


def verify_all(
    ticket_id: int,
    bk_biz_id: int,
    bk_cloud_id: int,
    ip: str,
    bk_host_id: int,
    regions: Optional[List[str]] = None,
) -> Dict[str, HostCheckResult]:
    """一键验证全部 4 个方法。

    :param ticket_id: 真实存在的单据 id（脱离场景下可以是任意合法单据）
    :param bk_biz_id: 业务 id
    :param bk_cloud_id: 云区域（0=直连）
    :param ip: 主机 IP
    :param bk_host_id: 主机 id
    :param regions: CLB 遍历的 region 列表，默认 ["南京"]
    :return: dict，key 为方法名，value 为 HostCheckResult
    边界：
      - Ticket 不存在 -> raise Ticket.DoesNotExist（提前失败，避免脏跑）
      - CLB / DNS / CC 接口不可达 -> 对应方法内部走 CHECK_ERROR 分支，不会抛出
    """
    _enable_debug_log()
    regions = regions or ["南京"]

    print("\n" + "#" * 80)
    print("# HostRevokeChecker Shell Verify")
    print(
        "# ticket_id={ticket_id}, bk_biz_id={bk_biz_id}, bk_cloud_id={bk_cloud_id}".format(
            ticket_id=ticket_id, bk_biz_id=bk_biz_id, bk_cloud_id=bk_cloud_id
        )
    )
    print(
        "# ip={ip}, bk_host_id={bk_host_id}, regions={regions}".format(ip=ip, bk_host_id=bk_host_id, regions=regions)
    )
    print("#" * 80)

    checker = _build_checker(
        ticket_id=ticket_id,
        bk_biz_id=bk_biz_id,
        bk_cloud_id=bk_cloud_id,
        ip=ip,
        bk_host_id=bk_host_id,
    )

    results: Dict[str, HostCheckResult] = {}
    results["check_in_ticket_scope"] = verify_check_in_ticket_scope(checker)
    results["check_clb_mapping"] = verify_check_clb_mapping(checker, regions=regions)
    results["check_dns_mapping"] = verify_check_dns_mapping(checker)
    results["check_dbm_metadata"] = verify_check_dbm_metadata(checker)

    # 汇总
    print("\n" + "#" * 80)
    print("# 汇总")
    print("#" * 80)
    for method, res in results.items():
        print(
            "  {method:32s} passed={passed}  reason_code={rc}".format(
                method=method, passed=res.passed, rc=res.reason_code
            )
        )
    return results


# ------------------------------------------------------------
# 边界场景快捷验证入口
# ------------------------------------------------------------


def verify_edge_cases(
    ticket_id: int,
    bk_biz_id: int,
    bk_cloud_id: int,
    ip: str,
    bk_host_id: int,
) -> None:
    """一键跑一遍所有"预期分支"的边界场景，用于确认 reason_code 覆盖全。

    观察内容：
      1) check_clb_mapping regions=[] -> NO_REGION_INPUT
      2) check_clb_mapping regions=["", "  "] -> NO_REGION_INPUT
      3) check_clb_mapping regions=["not-exist-region-xxx"] -> 视接口实现走 check_error 或 IP_NOT_REGISTERED_IN_CLB
      4) 幂等缓存：连续调 2 次 use_cache=True，第 2 次应命中缓存（观察日志只出现 1 次 API 调用）
    """
    _enable_debug_log()
    checker = _build_checker(
        ticket_id=ticket_id,
        bk_biz_id=bk_biz_id,
        bk_cloud_id=bk_cloud_id,
        ip=ip,
        bk_host_id=bk_host_id,
    )

    # 边界 1：regions=[]
    _dump("edge/regions_empty", checker.check_clb_mapping(regions=[]))
    # 边界 2：regions 全空串
    _dump("edge/regions_all_blank", checker.check_clb_mapping(regions=["", "  "]))
    # 边界 3：region 假名（观察异常处理）
    _dump("edge/regions_fake", checker.check_clb_mapping(regions=["not-exist-region-xxx"]))

    # 边界 4：DNS 幂等缓存
    r1 = checker.check_dns_mapping(use_cache=True)
    r2 = checker.check_dns_mapping(use_cache=True)
    _dump("edge/dns_cache_1st", r1)
    _dump("edge/dns_cache_2nd_should_be_same", r2)


# ============================================================
# 需求 7 · MySQL 主机进程存活检查（本地纯函数验证；不发 Job / 不查 DB）
# ============================================================


def verify_build_mysql_process_check_script(
    expected_proc_names: Optional[List[str]] = None,
) -> str:
    """本地渲染 MySQL 进程存活检查 shell 脚本并 print 到 stdout。

    用途：
      - 生成脚本文本，人工目视核查（白名单数组 / awk 分支 / <ctx> 输出等）
      - 可直接拷贝到测试机 root 身份 ``bash -x`` 复现

    :param expected_proc_names: 进程名白名单；None -> 走脚本生成器的默认值
        （mysqld / mysql-proxy / mariadbd）
    :return: str，渲染后的 shell 脚本内容
    边界：
      - 生成器抛 ValueError（白名单含非法字符） -> print 异常并 raise
      - 仅本地 print，不发 RPC、不写 DB、不下发 Job
    """
    # 局部 import 避免顶层引入生成器造成模块级循环
    from backend.flow.engine.revoke.scripts.mysql_process_check_script import build_mysql_process_check_script

    print("\n" + "#" * 80)
    print("# verify_build_mysql_process_check_script")
    print("# expected_proc_names={}".format(expected_proc_names))
    print("#" * 80)

    try:
        script = build_mysql_process_check_script(
            expected_proc_names=expected_proc_names,
        )
    except ValueError as err:
        print("[ValueError] {}".format(err))
        raise

    print("-" * 80)
    print(script)
    print("-" * 80)
    print("# END OF SCRIPT (chars={})".format(len(script)))
    return script


def verify_parse_process_check_result(sample_case: str = "ok") -> HostCheckResult:
    """本地用手工样例 JSON 调 :meth:`HostRevokeChecker.parse_process_check_result` 并 print 结果。

    覆盖 3 种 reason_code 场景（主机维度方案），通过 ``sample_case`` 切换：

      * ``"ok"``                 —— hits 为空，主机上无 MySQL 家族进程 LISTEN
      * ``"mysql_still_alive"``  —— hits 非空，至少一个 MySQL 家族进程仍在 LISTEN
      * ``"check_error"``        —— 脚本自身报 error（如非 root）

    :param sample_case: 样例场景名；不在上述枚举内 -> raise ValueError
    :return: :class:`HostCheckResult`，同时 print 到 stdout
    边界：
      - sample_case 非法 -> raise ValueError
      - 仅本地 print，不发 RPC、不写 DB
    """
    ip: str = "1.2.3.4"

    if sample_case == "ok":
        script_output: Dict[str, Any] = {
            "found_mysql_procs": False,
            "hits": [],
            "collect_tool": "ss",
            "error": None,
        }
    elif sample_case == "mysql_still_alive":
        script_output = {
            "found_mysql_procs": True,
            "hits": [
                {"port": 25000, "pid": 19898, "proc_name": "mysqld"},
                {"port": 26000, "pid": 21303, "proc_name": "mysqld"},
                {"port": 10000, "pid": 14057, "proc_name": "mysql-proxy"},
            ],
            "collect_tool": "ss",
            "error": None,
        }
    elif sample_case == "check_error":
        script_output = {
            "found_mysql_procs": False,
            "hits": [],
            "collect_tool": None,
            "error": "require root to see all processes",
        }
    else:
        raise ValueError(
            "unknown sample_case={!r}; must be one of " "['ok','mysql_still_alive','check_error']".format(sample_case)
        )

    print("\n" + "#" * 80)
    print("# verify_parse_process_check_result sample_case={}".format(sample_case))
    print("# ip={}".format(ip))
    print("# script_output={}".format(json.dumps(script_output, ensure_ascii=False)))
    print("#" * 80)

    result = HostRevokeChecker.parse_process_check_result(
        script_output_json=script_output,
        ip=ip,
    )
    _dump("parse_process_check_result[{}]".format(sample_case), result)
    return result


# ============================================================
# 用法示例（复制以下代码到 django shell 里跑，替换真实参数即可）
# ============================================================
#
# >>> from backend.flow.engine.revoke.scripts.shell_verify_host_check import (
# ...     verify_all, verify_edge_cases,
# ... )
#
# # 场景 A：一键跑全部 4 个方法
# >>> verify_all(
# ...     ticket_id=12345,          # 真实存在的单据 id
# ...     bk_biz_id=100,            # 业务 id
# ...     bk_cloud_id=0,            # 云区域，0 = 直连
# ...     ip="1.2.3.4",             # 真实存在的机器 IP
# ...     bk_host_id=1001,          # 真实存在的机器 bk_host_id
# ...     regions=["南京", "上海"], # CLB region 列表
# ... )
#
# # 场景 B：只跑边界分支验证
# >>> verify_edge_cases(
# ...     ticket_id=12345,
# ...     bk_biz_id=100,
# ...     bk_cloud_id=0,
# ...     ip="1.2.3.4",
# ...     bk_host_id=1001,
# ... )
#
# # 场景 C：逐个跑 & 拿到结果对象自己处理
# >>> from backend.flow.engine.revoke.scripts.shell_verify_host_check import (
# ...     _build_checker, verify_check_dns_mapping, verify_check_dbm_metadata,
# ...     _enable_debug_log,
# ... )
# >>> _enable_debug_log()
# >>> checker = _build_checker(
# ...     ticket_id=12345, bk_biz_id=100, bk_cloud_id=0,
# ...     ip="1.2.3.4", bk_host_id=1001,
# ... )
# >>> r = verify_check_dns_mapping(checker)
# >>> print(r.passed, r.reason_code)
# >>> print(r.evidence)
#
# # 场景 D：需求 7 · MySQL 主机进程存活检查（本地纯函数验证，不发 Job）
# >>> from backend.flow.engine.revoke.scripts.shell_verify_host_check import (
# ...     verify_build_mysql_process_check_script,
# ...     verify_parse_process_check_result,
# ... )
#
# # D-1：本地渲染脚本并 print（拷贝到目标机 root 身份 `bash -x` 复现）
# >>> verify_build_mysql_process_check_script(
# ...     expected_proc_names=["mysqld"],  # Storage 节点收窄
# ... )
#
# # D-2：本地跑 3 个 reason_code 样例（每次跑一个）
# >>> for case in ["ok", "mysql_still_alive", "check_error"]:
# ...     verify_parse_process_check_result(sample_case=case)
