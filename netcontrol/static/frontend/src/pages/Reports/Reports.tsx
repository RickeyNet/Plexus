import { useState } from 'react';

import { AvailabilityTab } from './AvailabilityTab';
import { BillingTab } from './BillingTab';
import { CapacityPlanningTab } from './CapacityPlanningTab';
import { GenerateReportTab } from './GenerateReportTab';
import { HistoryTab } from './HistoryTab';
import { OidProfilesTab } from './OidProfilesTab';
import { SyslogEventsTab } from './SyslogEventsTab';

type Tab = 'generate' | 'history' | 'capacity' | 'availability' | 'events' | 'oid-profiles' | 'billing';

const TABS: { value: Tab; label: string }[] = [
  { value: 'generate', label: 'Generate' },
  { value: 'history', label: 'History' },
  { value: 'capacity', label: 'Capacity Planning' },
  { value: 'availability', label: 'Availability' },
  { value: 'events', label: 'Syslog Events' },
  { value: 'oid-profiles', label: 'OID Profiles' },
  { value: 'billing', label: 'Bandwidth Billing' },
];

export function Reports() {
  const [tab, setTab] = useState<Tab>('generate');

  return (
    <div>
      <div className="page-header" style={{ marginBottom: '0.75rem' }}>
        <h2 style={{ margin: 0 }}>Reports</h2>
      </div>

      <div className="tab-controls">
        {TABS.map((t) => (
          <button
            key={t.value}
            type="button"
            className={`btn btn-sm btn-secondary upgrade-tab-btn${tab === t.value ? ' active' : ''}`}
            onClick={() => setTab(t.value)}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="card" style={{ padding: '1rem' }}>
        {tab === 'generate' && <GenerateReportTab />}
        {tab === 'history' && <HistoryTab />}
        {tab === 'capacity' && <CapacityPlanningTab />}
        {tab === 'availability' && <AvailabilityTab />}
        {tab === 'events' && <SyslogEventsTab />}
        {tab === 'oid-profiles' && <OidProfilesTab />}
        {tab === 'billing' && <BillingTab />}
      </div>
    </div>
  );
}
