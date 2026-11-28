import { lazy, Suspense } from 'react';

import { useAuthStatus } from '@/api/auth';
import { PageHeader } from '@/components/PageHeader';
import { PageHelp } from '@/components/PageHelp';
import { PageLoader } from '@/components/PageLoader';
import { TabBar } from '@/components/TabBar';
import { visibleTabs } from '@/lib/tabGating';
import { usePathTab } from '@/lib/usePathTab';

import { CONFIGURE_FEATURES } from './configureTabs';

// Each tab is its own chunk, fetched when the tab is first opened. A chunk
// that fails to load (stale deploy) reaches the route ErrorBoundary in App.
const DevicesTab = lazy(() => import('./DevicesTab').then((m) => ({ default: m.DevicesTab })));
const AlertsTab = lazy(() => import('./AlertsTab').then((m) => ({ default: m.AlertsTab })));
const EventsTab = lazy(() => import('./EventsTab').then((m) => ({ default: m.EventsTab })));
const SecurityTab = lazy(() => import('./SecurityTab').then((m) => ({ default: m.SecurityTab })));
const SlaTab = lazy(() => import('./SlaTab').then((m) => ({ default: m.SlaTab })));
const AvailabilityTab = lazy(() => import('./AvailabilityTab').then((m) => ({ default: m.AvailabilityTab })));
const CapacityTab = lazy(() => import('./CapacityTab').then((m) => ({ default: m.CapacityTab })));
const ConfigureTab = lazy(() => import('./ConfigureTab').then((m) => ({ default: m.ConfigureTab })));

type Tab = 'devices' | 'alerts' | 'events' | 'security' | 'sla' | 'availability' | 'capacity' | 'configure';

const BASE = '/monitoring';

// Route churn (formerly its own tab) is a filter on Alerts; the router sends
// /monitoring/routes there. Alert Rules, Suppressions, SLA Targets and OID
// Profiles live under Configure (/monitoring/configure/<sub>) together with
// the graph templates that used to be the standalone Graphs page; the router
// redirects their old paths. Configure shows when any of its sub-tabs would.
const TABS: { key: Tab; label: string; feature: string | string[] }[] = [
  { key: 'devices', label: 'Devices', feature: 'monitoring' },
  { key: 'alerts', label: 'Alerts', feature: 'monitoring' },
  { key: 'events', label: 'Events', feature: 'monitoring' },
  { key: 'security', label: 'Security', feature: 'monitoring' },
  { key: 'sla', label: 'SLA', feature: 'monitoring' },
  { key: 'availability', label: 'Availability', feature: 'monitoring' },
  { key: 'capacity', label: 'Capacity', feature: 'monitoring' },
  { key: 'configure', label: 'Configure', feature: CONFIGURE_FEATURES },
];
const TAB_KEYS = TABS.map((t) => t.key);
// Configure resolves /monitoring/configure/<sub> with its own usePathTab.
const NESTED: readonly Tab[] = ['configure'];

export function Monitoring() {
  const { data: auth } = useAuthStatus();
  const shownTabs = visibleTabs(TABS, auth);
  const [tab, selectTab] = usePathTab(
    BASE,
    TAB_KEYS,
    'devices',
    auth ? shownTabs.map((t) => t.key) : undefined,
    NESTED,
  );

  return (
    <div className="page">
      <PageHeader title="Monitoring" />

      <PageHelp
        guide="Monitoring"
        pageKey="monitoring"
        title="Real-Time Device Monitoring"
        text="Track CPU, memory, response time, packet loss, and interface status. Includes alerts, the syslog and SNMP trap event log, the IDS alerts of OPNsense firewalls (Security), SLA tracking, availability history and capacity planning trends. The Configure tab holds the setup behind them: alert rules, suppressions, SLA targets, custom OID profiles, and graph / host templates and graph trees."
      />

      <TabBar tabs={shownTabs} active={tab} onChange={selectTab} aria-label="Monitoring sections" />

      <Suspense fallback={<PageLoader />}>
        {tab === 'devices' && <DevicesTab />}
        {tab === 'alerts' && <AlertsTab />}
        {tab === 'events' && <EventsTab />}
        {tab === 'security' && <SecurityTab />}
        {tab === 'sla' && <SlaTab />}
        {tab === 'availability' && <AvailabilityTab />}
        {tab === 'capacity' && <CapacityTab />}
        {tab === 'configure' && <ConfigureTab />}
      </Suspense>
    </div>
  );
}
