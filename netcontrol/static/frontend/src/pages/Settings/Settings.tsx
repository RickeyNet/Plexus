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
import { ChatOpsTab } from './ChatOpsTab';
import { AuthTab } from './AuthTab';
import { CustomDataTab } from './CustomDataTab';
import { DeviceModelTab } from './DeviceModelTab';
import { DiscoveryTab } from './DiscoveryTab';
import { FeaturesTab } from './FeaturesTab';
import { GitSourcesTab } from './GitSourcesTab';
import { ChangeLogRetentionSection, JobRetentionSection } from './JobRetentionSection';
import { LoggingTab } from './LoggingTab';
import { MonitoringTab } from './MonitoringTab';
import { NetFlowTab } from './NetFlowTab';
import { NotificationsTab } from './NotificationsTab';
import { PluginsTab } from './PluginsTab';
import { SecretsProvidersTab } from './SecretsProvidersTab';
import { SiemTab } from './SiemTab';
import { SystemTab } from './SystemTab';
import { UnsavedContext, useUnsavedRegistry } from './unsaved-context';
import { UsersTab } from './UsersTab';
import { ValidationRulesTab } from './ValidationRulesTab';
import { WebhooksTab } from './WebhooksTab';

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
  | 'webhooks'
  | 'features'
  | 'custom-data'
  | 'device-model'
  | 'git-sources'
  | 'secrets-providers'
  | 'validation-rules'
  | 'ai-access'
  | 'chatops'
  | 'plugins'
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
    text: 'Send monitoring alerts to email, PagerDuty, a JSON webhook, Microsoft Teams, or the Slack and Webex ChatOps bots. Alert rules pick their own channels; alerts without a rule go to the channels marked Default.',
  },
  webhooks: {
    title: 'Event Webhooks',
    text: 'Send a signed HTTP request to a URL whenever a host, group, IPAM prefix or address, VLAN, VRF, credential, config backup or job is created, updated or deleted. Each webhook picks its objects, actions and optional groups; Deliveries shows every attempt and can send one again.',
  },
  features: {
    title: 'Feature Visibility',
    text: 'Choose which features appear in the navigation for every user, admins included. Hiding a feature removes it from the menu; it does not disable it.',
  },
  'custom-data': {
    title: 'Custom Fields & Tags',
    text: 'Define extra fields and tags for hosts, groups and IPAM prefixes. Values are set on the object itself.',
  },
  'device-model': {
    title: 'Device Model',
    text: 'Curate the manufacturers, device types, roles and lifecycle statuses that hosts link to. Discovery adds manufacturers and device types it finds; a value set by hand on a host is never overwritten. Sites are managed on the Geolocation page.',
  },
  'validation-rules': {
    title: 'Data Validation Rules',
    text: 'Require values to follow your conventions: a pattern, a length, a number range or a value at all. Rules are checked on the server whenever a host, group, IPAM prefix or address, VLAN, VRF or custom field value is saved in Plexus; discovery and syncs are not checked. Check existing data lists the stored objects that break a rule.',
  },
  'git-sources': {
    title: 'Git Sources',
    text: 'Keep templates, Ansible playbooks and config contexts in Git repositories. Each sync imports the branch head by folder (templates/, playbooks/, config_contexts/); imported records are read-only in Plexus, show their file and commit, and are removed when their file leaves the repository.',
  },
  'secrets-providers': {
    title: 'Secrets Providers',
    text: 'Connect HashiCorp Vault, AWS Secrets Manager or Azure Key Vault. Credentials and secret variables can then hold a reference (provider, path, key) instead of a stored value; Plexus reads the value when it is used and never shows it. Test checks one reference.',
  },
  chatops: {
    title: 'ChatOps',
    text: 'Run Plexus commands from Slack, Webex and Microsoft Teams: look up devices, interfaces, alerts, IP addresses and jobs, trace a path, acknowledge alerts and launch approved job presets. Set up each bot, map chat users to the Plexus users whose permissions their commands use, and review every command received.',
  },
  'ai-access': {
    title: 'AI Access',
    text: 'Let AI clients such as Claude read Plexus data through a read-only MCP endpoint: turn the endpoint on, set its limits, and create or revoke the tokens clients sign in with. Each token is limited to the data categories you choose and to what its owner can see, and every call is written to the audit log.',
  },
  plugins: {
    title: 'Plugins',
    text: 'Plugins installed on the server, with their version, status and any load or startup error. Only plugins named in the PLEXUS_PLUGINS setting load; each is gated by its own feature key, granted in Access Groups.',
  },
  system: {
    title: 'System & Updates',
    text: 'See the running version, choose the update channel, check for updates, and install or roll back an update through the host updater. Job history sets how long finished jobs are kept.',
  },
};

type TabItem = { key: Tab; label: string };

// The admin sections, grouped for the side navigation.
const ADMIN_GROUPS: { title: string; tabs: TabItem[] }[] = [
  {
    title: 'General',
    tabs: [
      { key: 'appearance', label: 'Appearance' },
      { key: 'features', label: 'Features' },
      { key: 'plugins', label: 'Plugins' },
      { key: 'system', label: 'System' },
    ],
  },
  {
    title: 'Access',
    tabs: [
      { key: 'users', label: 'Users' },
      { key: 'access-groups', label: 'Access Groups' },
      { key: 'auth', label: 'Authentication' },
      { key: 'secrets-providers', label: 'Secrets Providers' },
      { key: 'ai-access', label: 'AI Access' },
    ],
  },
  {
    title: 'Monitoring',
    tabs: [
      { key: 'discovery', label: 'Discovery' },
      { key: 'monitoring', label: 'Monitoring' },
      { key: 'netflow', label: 'NetFlow' },
    ],
  },
  {
    title: 'Alerts & logs',
    tabs: [
      { key: 'notifications', label: 'Notifications' },
      { key: 'webhooks', label: 'Webhooks' },
      { key: 'chatops', label: 'ChatOps' },
      { key: 'logging', label: 'Logging' },
      { key: 'siem', label: 'SIEM' },
    ],
  },
  {
    title: 'Data model',
    tabs: [
      { key: 'custom-data', label: 'Custom Fields & Tags' },
      { key: 'device-model', label: 'Device Model' },
      { key: 'validation-rules', label: 'Validation Rules' },
      { key: 'git-sources', label: 'Git Sources' },
    ],
  },
];
const TAB_KEYS = ADMIN_GROUPS.flatMap((g) => g.tabs.map((t) => t.key));

const NON_ADMIN_TABS: TabItem[] = [
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

      <div className="side-nav-layout">
        <SettingsNav active={tab} onSelect={(next) => void selectTab(next)} />

        <UnsavedContext.Provider value={unsaved}>
          <div className="card card-sm side-nav-main">
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
            {tab === 'webhooks' && <WebhooksTab />}
            {tab === 'features' && <FeaturesTab capabilities={caps} />}
            {tab === 'custom-data' && <CustomDataTab />}
            {tab === 'device-model' && <DeviceModelTab />}
            {tab === 'validation-rules' && <ValidationRulesTab />}
            {tab === 'git-sources' && <GitSourcesTab />}
            {tab === 'secrets-providers' && <SecretsProvidersTab />}
            {tab === 'ai-access' && <AiAccessTab />}
            {tab === 'chatops' && <ChatOpsTab />}
            {tab === 'plugins' && <PluginsTab />}
            {tab === 'system' && (
              <div className="stack">
                <SystemTab />
                {/* Outside SystemTab so an updater error does not hide it. */}
                <section>
                  <h4 style={{ margin: '0 0 0.5rem 0' }}>Job history</h4>
                  <JobRetentionSection />
                </section>
                <section>
                  <h4 style={{ margin: '0 0 0.5rem 0' }}>Change log</h4>
                  <ChangeLogRetentionSection />
                </section>
              </div>
            )}
          </div>
        </UnsavedContext.Provider>
      </div>
    </div>
  );
}

/**
 * Grouped section list beside the settings form. On narrow windows the list
 * gives way to one select with the same groups.
 */
function SettingsNav({ active, onSelect }: { active: Tab; onSelect: (next: Tab) => void }) {
  return (
    <nav className="side-nav card" aria-label="Settings sections">
      <select
        className="form-select side-nav-select"
        aria-label="Settings section"
        value={active}
        onChange={(e) => onSelect(e.target.value as Tab)}
      >
        {ADMIN_GROUPS.map((group) => (
          <optgroup key={group.title} label={group.title}>
            {group.tabs.map((t) => (
              <option key={t.key} value={t.key}>
                {t.label}
              </option>
            ))}
          </optgroup>
        ))}
      </select>
      <div className="side-nav-list">
        {ADMIN_GROUPS.map((group) => (
          <div key={group.title} className="side-nav-section">
            <div className="side-nav-heading">{group.title}</div>
            {group.tabs.map((t) => (
              <button
                key={t.key}
                type="button"
                className={`side-nav-link${t.key === active ? ' active' : ''}`}
                aria-current={t.key === active ? 'page' : undefined}
                onClick={() => onSelect(t.key)}
              >
                {t.label}
              </button>
            ))}
          </div>
        ))}
      </div>
    </nav>
  );
}
