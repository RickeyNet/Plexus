import { useId, useMemo, useState } from 'react';

import { useCloudAccounts, useCloudProviders } from '@/api/cloud';
import { PageHeader } from '@/components/PageHeader';
import { PageHelp } from '@/components/PageHelp';
import { QueryError } from '@/components/QueryError';
import { TabBar } from '@/components/TabBar';
import { UntestedBanner } from '@/components/UntestedBanner';
import { capitalize, cloudTerms } from '@/lib/cloudProviderTerms';
import { usePathTab } from '@/lib/usePathTab';
import { providerLabel } from './helpers';
import { AccountsTab } from './AccountsTab';
import { TopologyTab } from './TopologyTab';
import { FlowTab } from './FlowTab';
import { TrafficTab } from './TrafficTab';
import { PolicyTab } from './PolicyTab';

type Tab = 'accounts' | 'topology' | 'flow' | 'traffic' | 'policy';

const TABS: { key: Tab; label: string }[] = [
  { key: 'accounts', label: 'Accounts' },
  { key: 'topology', label: 'Topology' },
  { key: 'flow', label: 'Flow Logs' },
  { key: 'traffic', label: 'Traffic Metrics' },
  { key: 'policy', label: 'Policy' },
];
const TAB_KEYS = TABS.map((t) => t.key);

/** Help for a tab, in the words of the selected provider (all three for All providers). */
function tabHelp(tab: Tab, provider: string): { title: string; text: string } {
  const terms = cloudTerms(provider);
  const all = !terms.id;
  switch (tab) {
    case 'accounts':
      return {
        title: `Connected ${terms.scopeTitlePlural}`,
        text: `Register ${terms.scopeTitlePlural} so Plexus can read their network topology, ${terms.flowLogs} and ${terms.policy} and show them next to the on-prem devices. Live reads need the provider's SDK on the Plexus server; the Live reads row below shows which providers have it.`,
      };
    case 'topology':
      return {
        title: 'Hybrid topology',
        text: `${all ? 'VPCs, VNets' : terms.networks}, subnets and gateways next to the on-prem devices, to reason about hybrid paths between sites and cloud workloads.`,
      };
    case 'flow':
      return {
        title: capitalize(terms.flowLogs),
        text: all
          ? 'VPC Flow Logs from CloudWatch Logs (AWS) and Cloud Logging (GCP), NSG flow logs from a storage account (Azure): top talkers, top conversations, denied flows. Narrow them with the provider and account filters beside the tabs.'
          : `${terms.flowLogs} read from ${terms.flowSource}: top talkers, top conversations, denied flows. Narrow them with the provider and ${terms.scope} filters beside the tabs.`,
      };
    case 'traffic':
      return {
        title: 'Traffic metrics',
        text: `Bandwidth and packet metrics from ${all ? 'CloudWatch (AWS), Azure Monitor (Azure) and Cloud Monitoring (GCP)' : terms.metricsSource}, in the same view as on-prem interface counters.`,
      };
    case 'policy':
      return {
        title: 'Network policy',
        text: `Audit ${terms.policy} across the registered ${terms.scopeTitlePlural}: overly permissive rules and unused policies.`,
      };
  }
}

export interface CloudFilterState {
  provider: string;
  accountId: number | null;
}

export function CloudVisibility() {
  const fid = useId();
  const [tab, selectTab] = usePathTab('/cloud-visibility', TAB_KEYS, 'accounts');
  const [filter, setFilter] = useState<CloudFilterState>({ provider: '', accountId: null });

  const providers = useCloudProviders();
  const accounts = useCloudAccounts(filter.provider || undefined);

  const accountList = useMemo(() => accounts.data?.accounts ?? [], [accounts.data?.accounts]);
  const providerOptions = useMemo(() => {
    const fromApi = (providers.data?.providers ?? []).map((p) => p.id.toLowerCase());
    const fromAccts = accountList.map((a) => String(a.provider ?? '').toLowerCase());
    return [...new Set([...fromApi, ...fromAccts].filter(Boolean))].sort();
  }, [providers.data?.providers, accountList]);
  const filteredAccounts = filter.provider
    ? accountList.filter((a) => String(a.provider ?? '').toLowerCase() === filter.provider)
    : accountList;

  const help = tabHelp(tab, filter.provider);
  const filterTerms = cloudTerms(filter.provider);

  // Every tab reads the provider filter. The Accounts tab lists every
  // account of that provider, so the account filter shows only on the tabs
  // that narrow to one; it keeps its value while hidden.
  const filters = (
    <>
      <label className="text-muted" htmlFor={`${fid}-provider`}>Provider</label>
      <select
        id={`${fid}-provider`}
        className="form-select form-select-sm"
        value={filter.provider}
        onChange={(e) => setFilter({ provider: e.target.value, accountId: null })}
      >
        <option value="">All providers</option>
        {providerOptions.map((p) => (
          <option key={p} value={p}>{providerLabel(p)}</option>
        ))}
      </select>
      {tab !== 'accounts' && (
        <>
          <label className="text-muted" htmlFor={`${fid}-account`}>
            {filterTerms.id ? capitalize(filterTerms.scopeTitle) : 'Account'}
          </label>
          <select
            id={`${fid}-account`}
            className="form-select form-select-sm"
            value={filter.accountId ?? ''}
            onChange={(e) =>
              setFilter({ ...filter, accountId: e.target.value ? parseInt(e.target.value, 10) : null })
            }
          >
            <option value="">All {filterTerms.scopeTitlePlural}</option>
            {filteredAccounts.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name} ({providerLabel(a.provider)})
              </option>
            ))}
          </select>
        </>
      )}
    </>
  );

  return (
    <div className="page">
      <PageHeader title="Cloud Visibility" />

      <UntestedBanner feature="Cloud Visibility" />

      <TabBar
        tabs={TABS}
        active={tab}
        onChange={selectTab}
        aria-label="Cloud visibility sections"
        trailing={filters}
      />

      <PageHelp pageKey={`cloud-visibility.${tab}`} title={help.title} text={help.text} />

      {tab === 'accounts' && (
        <AccountsTab
          accounts={accountList}
          providerOptions={providerOptions.length ? providerOptions : ['aws', 'azure', 'gcp']}
          isLoading={accounts.isPending}
          loadError={
            accounts.isError && !accounts.data && (
              <QueryError what="cloud accounts" query={accounts} />
            )
          }
          providers={providers.data?.providers ?? []}
          providersError={
            providers.isError && !providers.data && (
              <QueryError what="cloud providers" query={providers} />
            )
          }
        />
      )}
      {tab === 'topology' && <TopologyTab filter={filter} />}
      {tab === 'flow' && <FlowTab filter={filter} />}
      {tab === 'traffic' && <TrafficTab filter={filter} />}
      {tab === 'policy' && <PolicyTab filter={filter} />}
    </div>
  );
}
