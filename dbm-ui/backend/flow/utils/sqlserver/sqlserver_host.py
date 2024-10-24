"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-DB管理系统(BlueKing-BK-DBM) available.
Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
from dataclasses import dataclass


@dataclass
class Host:
    """
    机器信息基类
    @attributes ip 机器ip，ipv4格式
    @attributes bk_cloud_id 机器所在云区域
    @attributes bk_host_id 机器所在cmdb的host_id
    """

    __dataclass_fields__ = None
    ip: str
    bk_cloud_id: int
    bk_host_id: int

    def __init__(self, **kwargs):
        for field in Host.__dataclass_fields__:
            setattr(self, field, kwargs.get(field))
