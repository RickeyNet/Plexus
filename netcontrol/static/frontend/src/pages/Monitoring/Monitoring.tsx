import { useState } from 'react';
import { useLocation, useNavigate } from 'react-router';

import { PageHelp } from '@/components/PageHelp';

import { DevicesTab } from './DevicesTab';
import { AlertsTab } from './AlertsTab';
import { EventsTab } from './EventsTab';
import { OidProfilesTab } from './OidProfilesTab';
import { RulesTab } from './RulesTab';
import { SuppressionsTab } from './SuppressionsTab';
import { SlaTab } from './SlaTab';
import { AvailabilityTab } from './AvailabilityTab';
import { CapacityTab } from './CapacityTab';

type Tab = 'devices' | 'alerts' | 'events' | 'rules' | 'suppressions' | 'sla' | 'availability' | 'capacity' | 'oid-profiles';

// Route churn (formerly its own tab) is a filter on Alerts; the router sends
// /monitoring/routes there. Events and OID Profiles moved here from Reports:
// both are served by monitoring-gated endpoints.
const TABS: { key: Tab; label: string; path: string }[] = [
  { key: 'devices', label: 'Devices', path: '/monitoring' },
  { key: 'alerts', label: 'Alerts', path: '/monitoring/alerts' },
  { key: 'events', label: 'Events', path: '/monitoring/events' },
  { key: 'rules', label: 'Alert Rules', path: '/monitoring/rules' },
  { key: 'suppressions', label: 'Suppressions', path: '/monitoring/suppressions' },
  { key: 'sla', label: 'SLA', path: '/monitoring/sla' },
  { key: 'availability', label: 'Availability', path: '/monitoring/availability' },
  { key: 'capacity', label: 'Capacity', path: '/monitoring/capacity' },
  { key: 'oid-profiles', label: 'OID Profiles', path: '/monitoring/oid-profiles' },
];

function tabFromPath(pathname: string): Tab {
  const match = TABS.find((t) => t.path === pathname);
  return match?.key ?? 'devices';
}

export function Monitoring() {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const [tab, setTab] = useState<Tab>(() => tabFromPath(pathname));

  const [prevPathname, setPrevPathname] = useState(pathname);
  if (pathname !== prevPathname) {
    setPrevPathname(pathname);
    setTab(tabFromPath(pathname));
  }

  function selectTab(t: Tab) {
    const target = TABS.find((x) => x.key === t)!;
    setTab(t);
    if (pathname !== target.path) navigate(target.path);
  }

  return (
    <div className="page">
      <div className="page-header">
        <h2>Monitoring</h2>
      </div>

      <PageHelp
        pageKey="monitoring"
        title="Real-Time Device Monitoring"
        text="Track CPU, memory, response time, packet loss, and interface status. Includes alerts, the syslog and SNMP trap event log, SLA tracking, availability history, capacity planning trends, and custom OID profiles."
      />

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

      {tab === 'devices' && <DevicesTab />}
      {tab === 'alerts' && <AlertsTab />}
      {tab === 'events' && <EventsTab />}
      {tab === 'rules' && <RulesTab />}
      {tab === 'suppressions' && <SuppressionsTab />}
      {tab === 'sla' && <SlaTab />}
      {tab === 'availability' && <AvailabilityTab />}
      {tab === 'capacity' && <CapacityTab />}
      {tab === 'oid-profiles' && <OidProfilesTab />}
    </div>
  );
}
