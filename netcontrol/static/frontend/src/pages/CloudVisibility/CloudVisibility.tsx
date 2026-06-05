import { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';

import { useCloudAccounts, useCloudProviders } from '@/api/cloud';
import { PageHelp } from '@/components/PageHelp';
import { UntestedBanner } from '@/components/UntestedBanner';
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

const TAB_HELP: Record<Tab, { title: string; text: string }> = {
  accounts: {
    title: 'Connected Cloud Accounts',
    text: 'Register AWS, Azure, and GCP accounts so Plexus can pull their network topology, flow logs, and policies. Capabilities depend on which cloud SDKs are installed on the server.',
  },
  topology: {
    title: 'Hybrid Topology',
    text: 'Cloud constructs (VPCs, subnets, gateways) rendered alongside on-prem devices. Use this to reason about hybrid connectivity paths and trace traffic between sites and cloud workloads.',
  },
  flow: {
    title: 'VPC Flow Logs',
    text: 'Query and aggregate cloud-native flow log records - top talkers, top conversations, denied flows. Filter by account and provider above.',
  },
  traffic: {
    title: 'Cloud Traffic Metrics',
    text: 'Bandwidth and connection metrics pulled from the cloud provider, normalized into the same view as on-prem interface stats.',
  },
  policy: {
    title: 'Cloud Network Policy',
    text: 'Audit security groups, NACLs, and firewall rules across registered cloud accounts. Spot overly-permissive rules and unused policies.',
  },
};

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

  useEffect(() => {
    setTab(tabFromPath(pathname));
  }, [pathname]);

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

  const tabHelp = TAB_HELP[tab];

  return (
    <div className="page">
      <div className="page-header">
        <h2>Cloud Visibility</h2>
      </div>

      <UntestedBanner feature="Cloud Visibility" />

      <PageHelp
        pageKey="cloud-visibility"
        title="Hybrid Cloud Network Visibility"
        text="Track AWS/Azure/GCP network constructs alongside on-prem devices. Manage cloud accounts, refresh topology snapshots, and view cloud and hybrid connectivity paths."
      />

      {/* Provider capability hints */}
      {(providers.data?.providers ?? []).length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.5rem', marginBottom: '0.75rem' }}>
          {(providers.data?.providers ?? []).map((p) => (
            <div key={p.id} className="card" style={{ padding: '0.65rem 0.85rem' }}>
              <strong>{providerLabel(p.id)}</strong>
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
          <label className="text-muted">Account:</label>
          <select
            className="form-select"
            value={filter.accountId ?? ''}
            onChange={(e) =>
              setFilter({ ...filter, accountId: e.target.value ? parseInt(e.target.value, 10) : null })
            }
          >
            <option value="">All Accounts</option>
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

      <PageHelp pageKey={`cloud-visibility.${tab}`} title={tabHelp.title} text={tabHelp.text} />

      {tab === 'accounts' && (
        <AccountsTab
          accounts={accountList}
          providerOptions={providerOptions.length ? providerOptions : ['aws', 'azure', 'gcp']}
          isLoading={accounts.isPending}
        />
      )}
      {tab === 'topology' && <TopologyTab filter={filter} />}
      {tab === 'flow' && <FlowTab filter={filter} />}
      {tab === 'traffic' && <TrafficTab filter={filter} />}
      {tab === 'policy' && <PolicyTab filter={filter} />}
    </div>
  );
}
