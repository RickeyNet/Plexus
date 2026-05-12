import { useState } from 'react';

import { PageHelp } from '@/components/PageHelp';
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

const TAB_HELP: Record<Tab, { title: string; text: string }> = {
  generate: {
    title: 'Generate a Report',
    text: 'Pick a report type - availability, compliance, utilization, network documentation - choose a scope and time range, and export to PDF or CSV.',
  },
  history: {
    title: 'Past Reports',
    text: 'Reports you (or scheduled jobs) have generated before. Re-download, share, or delete. Useful for showing auditors the historical record.',
  },
  capacity: {
    title: 'Capacity Planning',
    text: 'Trend interface and device utilization to project when links will run out of headroom. Sort by growth rate to find the next bottlenecks.',
  },
  availability: {
    title: 'Uptime & Availability',
    text: 'SLA-style availability summaries per device and per group. Use this for monthly reviews and to spot devices that quietly flap.',
  },
  events: {
    title: 'Syslog Events',
    text: 'Browse syslog and SNMP trap events ingested from devices. Filter by severity and host to investigate what happened around an incident.',
  },
  'oid-profiles': {
    title: 'Custom OID Profiles',
    text: 'Define extra SNMP OIDs to poll beyond the built-in metrics - vendor-specific counters, environmental sensors, anything walkable.',
  },
  billing: {
    title: 'Bandwidth Billing (95th Percentile)',
    text: 'Compute 95th-percentile billing figures from interface counters. Group circuits by customer or contract to produce monthly invoicing data.',
  },
};

export function Reports() {
  const [tab, setTab] = useState<Tab>('generate');

  return (
    <div>
      <div className="page-header" style={{ marginBottom: '0.75rem' }}>
        <h2 style={{ margin: 0 }}>Reports</h2>
      </div>

      <PageHelp
        pageKey="reports"
        title="Reports, Event Log & OID Profiles"
        text="Generate and export availability, compliance, utilization, and network documentation reports. View syslog events and SNMP traps. Manage custom OID profiles for monitoring."
      />

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

      <PageHelp pageKey={`reports.${tab}`} title={TAB_HELP[tab].title} text={TAB_HELP[tab].text} />

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
