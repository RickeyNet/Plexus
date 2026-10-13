import { useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router';

import { useAuthStatus } from '@/api/auth';
import { PageHelp } from '@/components/PageHelp';
import { TabBar } from '@/components/TabBar';
import { visibleTabs } from '@/lib/tabGating';
import { pathForTab, resolvePathTab } from '@/lib/tabPath';

import { DevicesTab } from './DevicesTab';
import { AlertsTab } from './AlertsTab';
import { EventsTab } from './EventsTab';
import { SlaTab } from './SlaTab';
import { AvailabilityTab } from './AvailabilityTab';
import { CapacityTab } from './CapacityTab';
import { ConfigureTab } from './ConfigureTab';
import { CONFIGURE_FEATURES } from './configureTabs';

type Tab = 'devices' | 'alerts' | 'events' | 'sla' | 'availability' | 'capacity' | 'configure';

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
  { key: 'sla', label: 'SLA', feature: 'monitoring' },
  { key: 'availability', label: 'Availability', feature: 'monitoring' },
  { key: 'capacity', label: 'Capacity', feature: 'monitoring' },
  { key: 'configure', label: 'Configure', feature: CONFIGURE_FEATURES },
];
const TAB_KEYS = TABS.map((t) => t.key);

/**
 * `usePathTab` for the top level, except that the Configure tab keeps its
 * sub-tab segment (/monitoring/configure/<sub>), which ConfigureTab resolves
 * with its own `usePathTab`. Any other tab is canonicalised to /monitoring/<tab>.
 */
function useMonitoringTab(allowed: readonly Tab[] | undefined): [Tab, (t: Tab) => void] {
  const { pathname, search, hash } = useLocation();
  const navigate = useNavigate();
  const segments = pathname.slice(BASE.length + 1).split('/').filter(Boolean);
  const topPath = segments.length ? `${BASE}/${segments[0]}` : BASE;
  const { tab, redirect } = resolvePathTab({ pathname: topPath, search, base: BASE, tabs: TAB_KEYS, defaultTab: 'devices', allowed });

  let target: { pathname: string; search: string } | null = redirect;
  if (!target && tab !== 'configure' && topPath !== pathname) target = { pathname: topPath, search };

  const targetPath = target?.pathname;
  const targetSearch = target?.search;
  useEffect(() => {
    if (targetPath === undefined) return;
    navigate({ pathname: targetPath, search: targetSearch, hash }, { replace: true });
  }, [targetPath, targetSearch, hash, navigate]);

  function selectTab(next: Tab) {
    if (next === tab) return; // keep the Configure sub-tab when re-clicking Configure
    const dest = pathForTab(BASE, next, 'devices');
    if (dest !== pathname) navigate(dest);
  }

  return [tab, selectTab];
}

export function Monitoring() {
  const { data: auth } = useAuthStatus();
  const shownTabs = visibleTabs(TABS, auth);
  const [tab, selectTab] = useMonitoringTab(auth ? shownTabs.map((t) => t.key) : undefined);

  return (
    <div className="page">
      <div className="page-header">
        <h2>Monitoring</h2>
      </div>

      <PageHelp
        pageKey="monitoring"
        title="Real-Time Device Monitoring"
        text="Track CPU, memory, response time, packet loss, and interface status. Includes alerts, the syslog and SNMP trap event log, SLA tracking, availability history and capacity planning trends. The Configure tab holds the setup behind them: alert rules, suppressions, SLA targets, custom OID profiles, and graph / host templates and graph trees."
      />

      <TabBar tabs={shownTabs} active={tab} onChange={selectTab} aria-label="Monitoring sections" />

      {tab === 'devices' && <DevicesTab />}
      {tab === 'alerts' && <AlertsTab />}
      {tab === 'events' && <EventsTab />}
      {tab === 'sla' && <SlaTab />}
      {tab === 'availability' && <AvailabilityTab />}
      {tab === 'capacity' && <CapacityTab />}
      {tab === 'configure' && <ConfigureTab />}
    </div>
  );
}
