import { useState } from 'react';
import { useLocation, useNavigate } from 'react-router';

import { useCloudAccounts, useCloudProviders } from '@/api/cloud';
import { PageHelp } from '@/components/PageHelp';
import { UntestedBanner } from '@/components/UntestedBanner';
import { capitalize, cloudProviderTerms, cloudTerms } from '@/lib/cloudProviderTerms';
import { providerLabel } from './helpers';
import { AccountsTab } from './AccountsTab';
import { TopologyTab } from './TopologyTab';
import { FlowTab } from './FlowTab';
import { TrafficTab } from './TrafficTab';
import { PolicyTab } from './PolicyTab';

type Tab = 'accounts' | 'topology' | 'flow' | 'traffic' | 'policy';

const TABS: { key: Tab; label: string; path: string }[] = [
  { key: 'accounts', label: 'Accounts', path: '/cloud-visibility' },
  { key: 'topology', label: 'Topology', path: '/cloud-visibility/topology' },
  { key: 'flow', label: 'Flow Logs', path: '/cloud-visibility/flow' },
  { key: 'traffic', label: 'Traffic Metrics', path: '/cloud-visibility/traffic' },
  { key: 'policy', label: 'Policy', path: '/cloud-visibility/policy' },
];

/** Help for a tab, in the words of the provider selected above (all three for All Providers). */
function tabHelp(tab: Tab, provider: string): { title: string; text: string } {
  const terms = cloudTerms(provider);
  const all = !terms.id;
  switch (tab) {
    case 'accounts':
      return {
        title: `Connected ${terms.scopeTitlePlural}`,
        text: `Register ${terms.scopeTitlePlural} so Plexus can read their network topology, ${terms.flowLogs} and ${terms.policy}. Live reads need the provider's SDK on the server (see the cards above).`,
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
          ? 'VPC Flow Logs from CloudWatch Logs (AWS) and Cloud Logging (GCP), NSG flow logs from a storage account (Azure): top talkers, top conversations, denied flows. Filter by provider and account above.'
          : `${terms.flowLogs} read from ${terms.flowSource}: top talkers, top conversations, denied flows. Filter by provider and ${terms.scope} above.`,
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

function tabFromPath(pathname: string): Tab {
  const match = TABS.find((t) => t.path === pathname);
  return match?.key ?? 'accounts';
}

export interface CloudFilterState {
  provider: string;
  accountId: number | null;
}

export function CloudVisibility() {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const [tab, setTab] = useState<Tab>(() => tabFromPath(pathname));
  const [filter, setFilter] = useState<CloudFilterState>({ provider: '', accountId: null });

  const [prevPathname, setPrevPathname] = useState(pathname);
  // Sync the active tab with the current route when navigation changes it.
  if (pathname !== prevPathname) {
    setPrevPathname(pathname);
    setTab(tabFromPath(pathname));
  }

  const providers = useCloudProviders();
  const accounts = useCloudAccounts(filter.provider || undefined);

  function selectTab(t: Tab) {
    const target = TABS.find((x) => x.key === t)!;
    setTab(t);
    if (pathname !== target.path) navigate(target.path);
  }

  const accountList = accounts.data?.accounts ?? [];
  const providerOptions = (() => {
    const fromApi = (providers.data?.providers ?? []).map((p) => p.id.toLowerCase());
    const fromAccts = accountList.map((a) => String(a.provider ?? '').toLowerCase());
    return [...new Set([...fromApi, ...fromAccts].filter(Boolean))].sort();
  })();
  const filteredAccounts = filter.provider
    ? accountList.filter((a) => String(a.provider ?? '').toLowerCase() === filter.provider)
    : accountList;

  const help = tabHelp(tab, filter.provider);
  const filterTerms = cloudTerms(filter.provider);

  return (
    <div className="page">
      <div className="page-header">
        <h2>Cloud Visibility</h2>
      </div>

      <UntestedBanner feature="Cloud Visibility" />

      <PageHelp
        pageKey="cloud-visibility"
        title="Hybrid Cloud Network Visibility"
        text="Track AWS, Azure and GCP network constructs alongside on-prem devices. Manage accounts, subscriptions and projects, refresh their topology, and view cloud and hybrid connectivity paths."
      />

      {/* Provider capability hints */}
      {(providers.data?.providers ?? []).length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.5rem', marginBottom: '0.75rem' }}>
          {(providers.data?.providers ?? []).map((p) => (
            <div key={p.id} className="card" style={{ padding: '0.65rem 0.85rem' }}>
              <strong>{providerLabel(p.id)}</strong>
              <span className="text-muted" style={{ marginLeft: '0.45rem' }}>
                {p.name || cloudProviderTerms(p.id).fullName}
              </span>
              <span
                className={`badge badge-${p.live_supported ? 'success' : 'warning'}`}
                style={{ marginLeft: '0.45rem' }}
              >
                {p.live_supported ? 'Live ready' : 'Live unavailable'}
              </span>
              {p.missing_dependencies?.length ? (
                <div className="text-muted" style={{ marginTop: '0.35rem', fontSize: '0.85em' }}>
                  Missing: {p.missing_dependencies.join(', ')}
                </div>
              ) : null}
            </div>
          ))}
        </div>
      )}

      {/* Provider + Account filters (apply to most tabs) */}
      <div className="card" style={{ padding: '0.75rem', marginBottom: '0.75rem' }}>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <label className="text-muted">Provider:</label>
          <select
            className="form-select"
            value={filter.provider}
            onChange={(e) => setFilter({ provider: e.target.value, accountId: null })}
          >
            <option value="">All Providers</option>
            {providerOptions.map((p) => (
              <option key={p} value={p}>{providerLabel(p)}</option>
            ))}
          </select>
          <label className="text-muted">{filterTerms.id ? `${capitalize(filterTerms.scopeTitle)}:` : 'Account:'}</label>
          <select
            className="form-select"
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
        </div>
      </div>

      <div role="tablist" style={{ marginBottom: '1rem', display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
        {TABS.map((t) => (
          <button
            key={t.key}
            role="tab"
            aria-selected={tab === t.key}
            className={`btn btn-sm btn-secondary mon-tab-btn${tab === t.key ? ' active' : ''}`}
            onClick={() => selectTab(t.key)}
          >
            {t.label}
          </button>
        ))}
      </div>

      <PageHelp pageKey={`cloud-visibility.${tab}`} title={help.title} text={help.text} />

      {tab === 'accounts' && (
        <AccountsTab
          accounts={accountList}
          providerOptions={providerOptions.length ? providerOptions : ['aws', 'azure', 'gcp']}
          isLoading={accounts.isPending}
          providers={providers.data?.providers ?? []}
        />
      )}
      {tab === 'topology' && <TopologyTab filter={filter} />}
      {tab === 'flow' && <FlowTab filter={filter} />}
      {tab === 'traffic' && <TrafficTab filter={filter} />}
      {tab === 'policy' && <PolicyTab filter={filter} />}
    </div>
  );
}
