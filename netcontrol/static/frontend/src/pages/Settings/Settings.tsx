import { useEffect, useRef } from 'react';

import { useAdminCapabilities } from '@/api/settings';
import { useAuthStatus } from '@/api/auth';
import { ApiError } from '@/api/client';
import { Callout } from '@/components/Callout';
import { useDialogs } from '@/components/DialogProvider-context';
import { LoadingState } from '@/components/LoadingState';
import { PageHeader } from '@/components/PageHeader';
import { PageHelp } from '@/components/PageHelp';
import { QueryError } from '@/components/QueryError';
import { TabBar } from '@/components/TabBar';
import { usePathTab } from '@/lib/usePathTab';

import { AccessGroupsTab } from './AccessGroupsTab';
import { AiAccessTab } from './AiAccessTab';
import { AppearanceTab } from './AppearanceTab';
import { AuthTab } from './AuthTab';
import { CustomDataTab } from './CustomDataTab';
import { DiscoveryTab } from './DiscoveryTab';
import { FeaturesTab } from './FeaturesTab';
import { JobRetentionSection } from './JobRetentionSection';
import { LoggingTab } from './LoggingTab';
import { MonitoringTab } from './MonitoringTab';
import { NetFlowTab } from './NetFlowTab';
import { NotificationsTab } from './NotificationsTab';
import { SiemTab } from './SiemTab';
import { SystemTab } from './SystemTab';
import { UnsavedContext, useUnsavedRegistry } from './unsaved-context';
import { UsersTab } from './UsersTab';

type Tab =
  | 'appearance'
  | 'users'
  | 'access-groups'
  | 'auth'
  | 'logging'
  | 'siem'
  | 'discovery'
  | 'monitoring'
  | 'netflow'
  | 'notifications'
  | 'features'
  | 'custom-data'
  | 'ai-access'
  | 'system';

// One intro per tab: describe only what the tab renders.
const TAB_HELP: Record<Tab, { title: string; text: string }> = {
  appearance: {
    title: 'Theme & Background',
    text: 'Choose the color theme and how strongly the space-depth background shows. Both are saved to this browser only.',
  },
  users: {
    title: 'User Accounts',
    text: "Create, edit and delete local user accounts, set each account's role and access groups, and reset passwords.",
  },
  'access-groups': {
    title: 'Access Groups',
    text: 'Each group grants view or modify access to a set of features. Users get that access through the groups they belong to.',
  },
  auth: {
    title: 'Authentication',
    text: 'Set login lockout, rate limit and idle timeout rules, and choose the sign-in provider (Local, RADIUS, TACACS+ or LDAP) with its settings and default access groups. Service credentials are the logins Plexus itself uses for polling and discovery.',
  },
  logging: {
    title: 'Syslog Forwarding',
    text: 'Forward Plexus application logs to a syslog server over UDP or TCP, and send a test message to check delivery.',
  },
  siem: {
    title: 'SIEM Audit-Event Forwarding',
    text: 'Forward audit events to one or more SIEM sinks. Each sink has its own protocol (UDP, TCP, TLS or HTTPS), payload format (CEF or ECS JSON) and severity floor.',
  },
  discovery: {
    title: 'Discovery & STP',
    text: 'Schedule topology discovery and STP polling, and define STP root policies that name the expected root bridge per group and VLAN.',
  },
  monitoring: {
    title: 'Monitoring Settings',
    text: 'Turn polling and route and VPN collection on or off, and set the poll interval, retention, CPU and memory alert thresholds, and alert cooldown and escalation. Poll Now runs one poll immediately.',
  },
  netflow: {
    title: 'NetFlow / sFlow Collector',
    text: 'Turn the UDP collector for NetFlow v5/v9, IPFIX and sFlow v5 on or off, set its listen ports, and choose how long raw flows and hourly summaries are kept.',
  },
  notifications: {
    title: 'Alert Notification Channels',
    text: 'Send monitoring alerts to email, PagerDuty, a JSON webhook or Microsoft Teams. Alert rules pick their own channels; alerts without a rule go to the channels marked Default.',
  },
  features: {
    title: 'Feature Visibility',
    text: 'Choose which features appear in the navigation for every user, admins included. Hiding a feature removes it from the menu; it does not disable it.',
  },
  'custom-data': {
    title: 'Custom Fields & Tags',
    text: 'Define extra fields and tags for hosts, groups and IPAM prefixes. Values are set on the object itself.',
  },
  'ai-access': {
    title: 'AI Access',
    text: 'Let AI clients such as Claude read Plexus data through a read-only MCP endpoint: turn the endpoint on, set its limits, and create or revoke the tokens clients sign in with. Each token is limited to the data categories you choose and to what its owner can see, and every call is written to the audit log.',
  },
  system: {
    title: 'System & Updates',
    text: 'See the running version, choose the update channel, check for updates, and install or roll back an update through the host updater. Job history sets how long finished jobs are kept.',
  },
};

const ADMIN_TABS: { key: Tab; label: string }[] = [
  { key: 'appearance', label: 'Appearance' },
  { key: 'users', label: 'Users' },
  { key: 'access-groups', label: 'Access Groups' },
  { key: 'auth', label: 'Authentication' },
  { key: 'logging', label: 'Logging' },
  { key: 'siem', label: 'SIEM' },
  { key: 'discovery', label: 'Discovery' },
  { key: 'monitoring', label: 'Monitoring' },
  { key: 'netflow', label: 'NetFlow' },
  { key: 'notifications', label: 'Notifications' },
  { key: 'features', label: 'Features' },
  { key: 'custom-data', label: 'Custom Fields & Tags' },
  { key: 'ai-access', label: 'AI Access' },
  { key: 'system', label: 'System' },
];
const TAB_KEYS = ADMIN_TABS.map((t) => t.key);

const NON_ADMIN_TABS: { key: Tab; label: string }[] = [
  { key: 'appearance', label: 'Appearance' },
];
const NON_ADMIN_KEYS = NON_ADMIN_TABS.map((t) => t.key);

export function Settings() {
  const auth = useAuthStatus();
  const isAdmin = auth.data?.role === 'admin';
  const capabilities = useAdminCapabilities();
  const [tab, navigateToTab] = usePathTab(
    '/settings',
    TAB_KEYS,
    'appearance',
    !auth.data ? undefined : isAdmin ? TAB_KEYS : NON_ADMIN_KEYS,
  );
  const unsaved = useUnsavedRegistry();
  const { confirm } = useDialogs();

  // Switching tabs unmounts the open form, so ask before dropping its edits.
  async function selectTab(next: Tab) {
    if (next === tab) return;
    const forms = unsaved.labels();
    if (forms.length > 0) {
      const ok = await confirm({
        title: 'Discard unsaved changes',
        message: `${forms.join(', ')} ${forms.length === 1 ? 'has' : 'have'} unsaved changes. Leave this tab and discard them?`,
        confirmLabel: 'Discard changes',
        cancelLabel: 'Keep editing',
      });
      if (!ok) return;
    }
    navigateToTab(next);
  }

  // The admin tab row scrolls sideways on narrow windows; keep the open tab
  // in view after a switch or a deep link.
  const tabBarRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const active = tabBarRef.current?.querySelector<HTMLElement>('[role="tab"][aria-selected="true"]');
    active?.scrollIntoView?.({ block: 'nearest', inline: 'nearest' });
  }, [tab, capabilities.data]);

  if (auth.isLoading) {
    return (
      <div>
        <PageHeader title="Settings" />
        <LoadingState />
      </div>
    );
  }

  if (!isAdmin) {
    return (
      <div>
        <PageHeader title="Settings" />

        <TabBar tabs={NON_ADMIN_TABS} active={tab} onChange={(next) => void selectTab(next)} aria-label="Settings sections" />

        <div className="card card-sm">
          <AppearanceTab />
        </div>
      </div>
    );
  }

  if (capabilities.isError && !capabilities.data) {
    const status =
      capabilities.error instanceof ApiError ? capabilities.error.status : null;
    return (
      <div>
        <PageHeader title="Settings" />
        {status === 401 || status === 403 ? (
          <Callout tone="danger">Admin access is required to view settings.</Callout>
        ) : (
          <QueryError what="settings" query={capabilities} />
        )}
      </div>
    );
  }

  if (!capabilities.data) {
    return (
      <div>
        <PageHeader title="Settings" />
        <LoadingState />
      </div>
    );
  }

  const caps = capabilities.data;

  return (
    <div>
      <PageHeader title="Settings" />

      <div ref={tabBarRef}>
        <TabBar
          tabs={ADMIN_TABS}
          active={tab}
          onChange={(next) => void selectTab(next)}
          className="tab-bar-oneline"
          aria-label="Settings sections"
        />
      </div>

      <UnsavedContext.Provider value={unsaved}>
        <div className="card card-sm">
          <PageHelp pageKey={`settings.${tab}`} title={TAB_HELP[tab].title} text={TAB_HELP[tab].text} />
          {tab === 'appearance' && <AppearanceTab />}
          {tab === 'users' && <UsersTab />}
          {tab === 'access-groups' && <AccessGroupsTab capabilities={caps} />}
          {tab === 'auth' && <AuthTab capabilities={caps} />}
          {tab === 'logging' && <LoggingTab />}
          {tab === 'siem' && <SiemTab />}
          {tab === 'discovery' && <DiscoveryTab />}
          {tab === 'monitoring' && <MonitoringTab />}
          {tab === 'netflow' && <NetFlowTab />}
          {tab === 'notifications' && <NotificationsTab />}
          {tab === 'features' && <FeaturesTab capabilities={caps} />}
          {tab === 'custom-data' && <CustomDataTab />}
          {tab === 'ai-access' && <AiAccessTab />}
          {tab === 'system' && (
            <div className="stack">
              <SystemTab />
              {/* Outside SystemTab so an updater error does not hide it. */}
              <section>
                <h4 style={{ margin: '0 0 0.5rem 0' }}>Job history</h4>
                <JobRetentionSection />
              </section>
            </div>
          )}
        </div>
      </UnsavedContext.Provider>
    </div>
  );
}
