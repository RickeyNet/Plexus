import { useState } from 'react';

import { useAdminCapabilities } from '@/api/settings';
import { ApiError } from '@/api/client';

import { AccessGroupsTab } from './AccessGroupsTab';
import { AuthTab } from './AuthTab';
import { DiscoveryTab } from './DiscoveryTab';
import { FeaturesTab } from './FeaturesTab';
import { LoggingTab } from './LoggingTab';
import { MonitoringTab } from './MonitoringTab';
import { UsersTab } from './UsersTab';

type Tab =
  | 'users'
  | 'access-groups'
  | 'auth'
  | 'logging'
  | 'discovery'
  | 'monitoring'
  | 'features';

const TABS: { id: Tab; label: string }[] = [
  { id: 'users', label: 'Users' },
  { id: 'access-groups', label: 'Access Groups' },
  { id: 'auth', label: 'Authentication' },
  { id: 'logging', label: 'Logging' },
  { id: 'discovery', label: 'Discovery' },
  { id: 'monitoring', label: 'Monitoring' },
  { id: 'features', label: 'Features' },
];

export function Settings() {
  const capabilities = useAdminCapabilities();
  const [tab, setTab] = useState<Tab>('users');

  if (capabilities.isLoading) {
    return (
      <div>
        <div className="page-header">
          <h2 style={{ margin: 0 }}>Settings</h2>
        </div>
        <p className="text-muted">Loading…</p>
      </div>
    );
  }

  if (capabilities.isError) {
    const status =
      capabilities.error instanceof ApiError ? capabilities.error.status : null;
    const message =
      status === 401 || status === 403
        ? 'Admin access is required to view settings.'
        : `Failed to load settings: ${(capabilities.error as Error).message}`;
    return (
      <div>
        <div className="page-header">
          <h2 style={{ margin: 0 }}>Settings</h2>
        </div>
        <div className="error">{message}</div>
      </div>
    );
  }

  const caps = capabilities.data!;

  return (
    <div>
      <div
        className="page-header"
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '0.5rem',
          marginBottom: '0.75rem',
        }}
      >
        <h2 style={{ margin: 0 }}>Settings</h2>
      </div>

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.5rem 0.75rem',
            borderBottom: '1px solid var(--border)',
            flexWrap: 'wrap',
          }}
        >
          {TABS.map((t) => (
            <button
              key={t.id}
              className={`btn btn-sm ${tab === t.id ? 'btn-primary' : 'btn-ghost'}`}
              onClick={() => setTab(t.id)}
            >
              {t.label}
            </button>
          ))}
        </div>
        <div style={{ padding: '0.75rem' }}>
          {tab === 'users' && <UsersTab />}
          {tab === 'access-groups' && <AccessGroupsTab capabilities={caps} />}
          {tab === 'auth' && <AuthTab capabilities={caps} />}
          {tab === 'logging' && <LoggingTab />}
          {tab === 'discovery' && <DiscoveryTab />}
          {tab === 'monitoring' && <MonitoringTab />}
          {tab === 'features' && <FeaturesTab capabilities={caps} />}
        </div>
      </div>
    </div>
  );
}
