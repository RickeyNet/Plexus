import { useState } from 'react';

import { PageHelp } from '@/components/PageHelp';
import { BillingTab } from './BillingTab';
import { GenerateReportTab } from './GenerateReportTab';
import { HistoryTab } from './HistoryTab';

// Availability, capacity planning, the syslog event log and OID profiles live
// under Monitoring (monitoring-gated endpoints); Reports only exports them.
type Tab = 'generate' | 'history' | 'billing';

const TABS: { value: Tab; label: string }[] = [
  { value: 'generate', label: 'Generate' },
  { value: 'history', label: 'History' },
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
        title="Reports"
        text="Generate and export availability, compliance, utilization, and network documentation reports, browse past runs, and produce 95th-percentile bandwidth billing."
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
        {tab === 'billing' && <BillingTab />}
      </div>
    </div>
  );
}
