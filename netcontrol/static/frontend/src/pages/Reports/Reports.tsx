import { PageHeader } from '@/components/PageHeader';
import { PageHelp } from '@/components/PageHelp';
import { TabBar } from '@/components/TabBar';
import { usePathTab } from '@/lib/usePathTab';

import { BillingTab } from './BillingTab';
import { GenerateReportTab } from './GenerateReportTab';
import { HistoryTab } from './HistoryTab';

// Availability, capacity planning, the syslog event log and OID profiles live
// under Monitoring (monitoring-gated endpoints); Reports only exports them.
type Tab = 'generate' | 'history' | 'billing';

const TABS: { key: Tab; label: string }[] = [
  { key: 'generate', label: 'Generate' },
  { key: 'history', label: 'History' },
  { key: 'billing', label: 'Bandwidth Billing' },
];
const TAB_KEYS = TABS.map((t) => t.key);

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
  const [tab, selectTab] = usePathTab('/reports', TAB_KEYS, 'generate');

  return (
    <div>
      <PageHeader title="Reports" />

      <PageHelp
        pageKey="reports"
        title="Reports"
        text="Generate and export availability, compliance, utilization, and network documentation reports, browse past runs, and produce 95th-percentile bandwidth billing."
      />

      <TabBar tabs={TABS} active={tab} onChange={selectTab} aria-label="Reports sections" />

      <PageHelp pageKey={`reports.${tab}`} title={TAB_HELP[tab].title} text={TAB_HELP[tab].text} />

      <div className="card">
        {tab === 'generate' && <GenerateReportTab />}
        {tab === 'history' && <HistoryTab />}
        {tab === 'billing' && <BillingTab />}
      </div>
    </div>
  );
}
