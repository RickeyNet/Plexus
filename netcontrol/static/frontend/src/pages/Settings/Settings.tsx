import { useState } from 'react';

import { useAdminCapabilities } from '@/api/settings';
import { useAuthStatus } from '@/api/auth';
import { ApiError } from '@/api/client';
import { PageHelp } from '@/components/PageHelp';

import { AccessGroupsTab } from './AccessGroupsTab';
import { AppearanceTab } from './AppearanceTab';
import { AuthTab } from './AuthTab';
import { DiscoveryTab } from './DiscoveryTab';
import { FeaturesTab } from './FeaturesTab';
import { LoggingTab } from './LoggingTab';
import { MonitoringTab } from './MonitoringTab';
import { NetFlowTab } from './NetFlowTab';
import { UsersTab } from './UsersTab';

type Tab =
  | 'appearance'
  | 'users'
  | 'access-groups'
  | 'auth'
  | 'logging'
  | 'discovery'
  | 'monitoring'
  | 'netflow'
  | 'features';

const TAB_HELP: Record<Tab, { title: string; text: string }> = {
  appearance: {
    title: 'Theme & UI Preferences',
    text: 'Per-user choices: theme, density, animations, and other visual options. These are local to your browser profile.',
  },
  users: {
    title: 'User Accounts',
    text: 'Add, disable, and reset passwords for local users. For SSO/RADIUS-backed accounts, see the Authentication tab — those map to external identities, not entries here.',
  },
  'access-groups': {
    title: 'Role-Based Access Groups',
    text: 'Define which features and inventory groups each role can see. Users get access by membership in one or more groups.',
  },
  auth: {
    title: 'Authentication Sources',
    text: 'Configure SAML SSO, LDAP, RADIUS, and local password policy. The active source(s) determine how users log in and which groups they map to.',
  },
  logging: {
    title: 'Application & Audit Logging',
    text: 'Application log level, audit log retention, and where to ship logs (file, syslog, etc.). Enable detailed logging when troubleshooting; turn it back down afterwards.',
  },
  discovery: {
    title: 'Network Discovery Defaults',
    text: 'Default credentials and discovery scope used when adding new devices via the Inventory page. These apply to manual and scheduled discovery alike.',
  },
  monitoring: {
    title: 'Monitoring Settings',
    text: 'Polling intervals, alert thresholds, retention windows, and which metrics get collected by default. Per-device overrides are possible from the device detail page.',
  },
  netflow: {
    title: 'NetFlow / sFlow Collector',
    text: 'Toggle the UDP collector for NetFlow v5/v9, IPFIX, and sFlow v5; change listen ports and how long raw flows and hourly summaries are retained. Changes apply immediately — no restart needed.',
  },
  features: {
    title: 'Feature Visibility',
    text: 'Hide or show features for the entire instance. Use this to declutter the UI for operators who only need a subset of Plexus, or to stage rollouts.',
  },
};

const ADMIN_TABS: { id: Tab; label: string }[] = [
  { id: 'appearance', label: 'Appearance' },
  { id: 'users', label: 'Users' },
  { id: 'access-groups', label: 'Access Groups' },
  { id: 'auth', label: 'Authentication' },
  { id: 'logging', label: 'Logging' },
  { id: 'discovery', label: 'Discovery' },
  { id: 'monitoring', label: 'Monitoring' },
  { id: 'netflow', label: 'NetFlow' },
  { id: 'features', label: 'Features' },
];

const NON_ADMIN_TABS: { id: Tab; label: string }[] = [
  { id: 'appearance', label: 'Appearance' },
];

export function Settings() {
  const auth = useAuthStatus();
  const isAdmin = auth.data?.role === 'admin';
  const capabilities = useAdminCapabilities();
  const [tab, setTab] = useState<Tab>('appearance');

  if (auth.isLoading) {
    return (
      <div>
        <div className="page-header">
          <h2 style={{ margin: 0 }}>Settings</h2>
        </div>
        <p className="text-muted">Loading…</p>
      </div>
    );
  }

  if (!isAdmin) {
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
            {NON_ADMIN_TABS.map((t) => (
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
            <AppearanceTab />
          </div>
        </div>
      </div>
    );
  }

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

      <PageHelp
        pageKey="settings"
        title="Application Settings"
        text="Configure polling intervals, feature toggles, default credentials, and other application-wide settings. Admin access required."
      />

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
          {ADMIN_TABS.map((t) => (
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
          <PageHelp pageKey={`settings.${tab}`} title={TAB_HELP[tab].title} text={TAB_HELP[tab].text} />
          {tab === 'appearance' && <AppearanceTab />}
          {tab === 'users' && <UsersTab />}
          {tab === 'access-groups' && <AccessGroupsTab capabilities={caps} />}
          {tab === 'auth' && <AuthTab capabilities={caps} />}
          {tab === 'logging' && <LoggingTab />}
          {tab === 'discovery' && <DiscoveryTab />}
          {tab === 'monitoring' && <MonitoringTab />}
          {tab === 'netflow' && <NetFlowTab />}
          {tab === 'features' && <FeaturesTab capabilities={caps} />}
        </div>
      </div>
    </div>
  );
}
