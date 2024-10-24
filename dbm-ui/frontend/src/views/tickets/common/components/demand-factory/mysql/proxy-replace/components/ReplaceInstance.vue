<!--
 * TencentBlueKing is pleased to support the open source community by making 蓝鲸智云-DB管理系统(BlueKing-BK-DBM) available.
 *
 * Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
 *
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License athttps://opensource.org/licenses/MIT
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
 * the specific language governing permissions and limitations under the License.
-->

<template>
  <DbOriginalTable
    :columns="columns"
    :data="tableData" />
</template>

<script setup lang="tsx">
  import { useI18n } from 'vue-i18n';

  import type { MySQLProxySwitchDetails } from '@services/model/ticket/details/mysql';
  import TicketModel from '@services/model/ticket/ticket';
  import { checkInstance } from '@services/source/dbbase';

  interface Props {
    ticketDetails: TicketModel<MySQLProxySwitchDetails>
  }

  interface RowData {
    originProxy: string;
    relatedClusters: string[];
    targetProxy: string;
  }

  const props = defineProps<Props>();

  const { t } = useI18n();

  const columns = [
    {
      label: t('目标Proxy主机'),
      field: 'originProxy',
      minWidth: 150,
      width: 220,
    },
    {
      label: t('同机关联集群'),
      field: 'relatedClusters',
      width: 220,
      render: ({ data }: { data: RowData }) => data.relatedClusters.map((item) => <p>{item}</p>),
    },
    {
      label: t('新proxy主机'),
      field: 'targetProxy',
      minWidth: 150,
      width: 220,
    },
  ];

  const relatedClusters = shallowRef<Record<string, string[]>>({});
  const tableData = shallowRef<RowData[]>([]);

  watch(
    () => props.ticketDetails.details,
    () => {
      const instanceAddresses = props.ticketDetails.details.infos.map(item => `${item.origin_proxy.ip}:${item.origin_proxy.port}`);
      checkInstance({
        instance_addresses: instanceAddresses,
        bk_biz_id: props.ticketDetails.bk_biz_id,
      }).then((data) => {
        data.forEach(item => {
          relatedClusters.value[item.instance_address] = item.related_clusters.map(cluster => cluster.master_domain);
        });
        tableData.value = props.ticketDetails.details.infos.map(item => {
          const instance = `${item.origin_proxy.ip}:${item.origin_proxy.port}`;
          return {
            originProxy: instance,
            relatedClusters: relatedClusters.value[instance] || [],
            targetProxy: item.target_proxy.ip,
          }
        });
      })
    },
    {
      immediate: true
    }
  )
</script>

<style lang="less" scoped>
  @import '@views/tickets/common/styles/DetailsTable.less';
</style>
