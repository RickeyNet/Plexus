import { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';

import { PageHelp } from '@/components/PageHelp';

import { DevicesTab } from './DevicesTab';
import { AlertsTab } from './AlertsTab';
import { RoutesTab } from './RoutesTab';
import { RulesTab } from './RulesTab';
import { SuppressionsTab } from './SuppressionsTab';
import { SlaTab } from './SlaTab';
import { AvailabilityTab } from './AvailabilityTab';
import { CapacityTab } from './CapacityTab';

type Tab = 'devices' | 'alerts' | 'routes' | 'rules' | 'suppressions' | 'sla' | 'availability' | 'capacity';

const TABS: { key: Tab; label: string; path: string }[] = [
  { key: 'devices', label: 'Devices', path: '/monitoring' },
  { key: 'alerts', label: 'Alerts', path: '/monitoring/alerts' },
  { key: 'routes', label: 'Route Churn', path: '/monitoring/routes' },
  { key: 'rules', label: 'Alert Rules', path: '/monitoring/rules' },
  { key: 'suppressions', label: 'Suppressions', path: '/monitoring/suppressions' },
  { key: 'sla', label: 'SLA', path: '/monitoring/sla' },
  { key: 'availability', label: 'Availability', path: '/monitoring/availability' },
  { key: 'capacity', label: 'Capacity', path: '/monitoring/capacity' },
];

function tabFromPath(pathname: string): Tab {
  const match = TABS.find((t) => t.path === pathname);
  return match?.key ?? 'devices';
}

export function Monitoring() {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const [tab, setTab] = useState<Tab>(() => tabFromPath(pathname));

  useEffect(() => {
    setTab(tabFromPath(pathname));
  }, [pathname]);

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
        text="Track CPU, memory, response time, packet loss, and interface status. Includes SLA tracking, availability history, and capacity planning trends."
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
      {tab === 'routes' && <RoutesTab />}
      {tab === 'rules' && <RulesTab />}
      {tab === 'suppressions' && <SuppressionsTab />}
      {tab === 'sla' && <SlaTab />}
      {tab === 'availability' && <AvailabilityTab />}
      {tab === 'capacity' && <CapacityTab />}
    </div>
  );
}
