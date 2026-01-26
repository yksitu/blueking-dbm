"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-DB管理系统(BlueKing-BK-DBM) available.
Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
import datetime
import json
import re

from django.utils import timezone
from django.utils.translation import gettext as _
from pipeline.component_framework.component import Component
from pipeline.core.flow import StaticIntervalGenerator

from backend.core import notify
from backend.db_meta.models import Cluster
from backend.dbm_aiagent.agent.commands import QueryAlarmInfoCommand
from backend.dbm_aiagent.agent.handlers import AgentHandler
from backend.flow.models import FlowTree
from backend.flow.plugins.components.collections.common.sidecar_service_abc import SidecarServiceABC
from backend.utils.time import datetime2str

cpl = re.compile(r"\[ai_result](?P<context>.+?)\[ai_result]")


class CheckClusterAlarmForAIService(SidecarServiceABC):
    """
    定义单据值守通用的component
    检查单据运行期间， 通过AI方式计算出对应集群信息，所产生的告警记录
    收集到告警记录，推送给DBA+提单者
    """

    interval = StaticIntervalGenerator(30)

    def sidecar_func(self, data, parent_data) -> bool:
        kwargs = data.get_one_of_inputs("kwargs")
        global_data = data.get_one_of_inputs("global_data")

        cluster_ids = kwargs["cluster_ids"]
        root_id = global_data["job_root_id"]
        flow_tree = FlowTree.objects.get(root_id=root_id)
        flow_start_time = flow_tree.created_at
        ticket_id = int(flow_tree.uid)
        now_time = datetime.datetime.now(timezone.utc)

        clusters = Cluster.objects.filter(id__in=cluster_ids)
        if not clusters:
            self.log_error(_("查询集群元数据为空，请检查传入的cluster_ids列表是否有问题:{}".format(cluster_ids)))
            return False
        cluster_domains = [c.immute_domain for c in clusters]
        self.log_info(_("监听集群有：{}".format(cluster_domains)))
        self.log_info(_("监听的时间区间是：{}-{}".format(datetime2str(flow_start_time), datetime2str(now_time))))

        ai_result = AgentHandler.ask_agent_with_command(
            command=QueryAlarmInfoCommand.command,
            command_params={
                "bk_biz_id": clusters[0].bk_biz_id,
                "cluster_domains": cluster_domains,
                "start_time": datetime2str(flow_start_time),
                "end_time": datetime2str(now_time),
            },
        )
        self.log_info(_("智能体输出的结果：{}".format(ai_result)))
        # 根据ai的分析结果，捕捉是否推送的用户的关键信息
        is_send_info = json.loads(re.search(cpl, ai_result).group("context"))
        if is_send_info and is_send_info.get("is_send_user"):
            # 从智能体根据结果分析来看， 结果为高风险，需要推送给提单者
            # 通过机器人给相关人员推送信息
            # 过滤无效信息
            self.log_info(_("正在把AI分析结果推送给提单者..."))
            send_result = ai_result.replace('[ai_result]{"is_send_user": true}[ai_result]', "")
            notify.send_msg_for_ai_task_guardian(ticket_id=ticket_id, ai_result=send_result)
            self.log_info(_("推送完成"))

        return True


class CheckClusterAlarmForAIComponent(Component):
    name = __name__
    code = "sidecar_check_cluster_alarm_for_ai"
    bound_service = CheckClusterAlarmForAIService
