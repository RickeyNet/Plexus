import { useState } from 'react';

import { PageHelp } from '@/components/PageHelp';
import { BackupsTab } from './BackupsTab';
import { DriftTab } from './DriftTab';
import { SearchTab } from './SearchTab';
import { ConfigJobStreamModal } from './ConfigJobStreamModal';

type Tab = 'drift' | 'policies' | 'history' | 'search';

const TABS: { value: Tab; label: string }[] = [
  { value: 'drift', label: 'Config Drift' },
  { value: 'policies', label: 'Backup Policies' },
  { value: 'history', label: 'Backup History' },
  { value: 'search', label: 'Config Search' },
];

const TAB_HELP: Record<Tab, { title: string; text: string }> = {
  drift: {
    title: 'Detect & Revert Configuration Drift',
    text: 'Capture a known-good baseline per device, then watch for unexpected changes against it. Diff drift events, revert to baseline, or accept the new config as the new baseline.',
  },
  policies: {
    title: 'Scheduled Backup Policies',
    text: 'Define which devices get backed up, how often, and how long backups are retained. One policy can cover many devices via inventory groups.',
  },
  history: {
    title: 'Backup History',
    text: 'Browse captured config backups, diff any two versions, and restore a device to a prior state. Backups are also available as evidence for compliance audits.',
  },
  search: {
    title: 'Search Across All Configs',
    text: 'Full-text search the latest configs of every device - find which switches use a deprecated SNMP community, who still has Telnet enabled, etc.',
  },
};

export function Configuration() {
  const [tab, setTab] = useState<Tab>('drift');
  const [captureJob, setCaptureJob] = useState<string | null>(null);
  const [revertJob, setRevertJob] = useState<string | null>(null);

  const tabHelp = TAB_HELP[tab];

  return (
    <div>
      <div className="page-header" style={{ marginBottom: '0.75rem' }}>
        <h2 style={{ margin: 0 }}>Configuration</h2>
      </div>

      <PageHelp
        pageKey="configuration"
        title="Configuration Management"
        text="Manage device configurations in one place. Detect drift against baselines, schedule automatic backups, browse backup history, and restore previous configurations."
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

      <PageHelp pageKey={`configuration.${tab}`} title={tabHelp.title} text={tabHelp.text} />

      <div className="card" style={{ padding: '1rem' }}>
        {tab === 'drift' && (
          <DriftTab
            onCaptureStarted={(jobId) => setCaptureJob(jobId)}
            onRevertStarted={(jobId) => setRevertJob(jobId)}
          />
        )}
        {(tab === 'policies' || tab === 'history') && (
          <BackupsTab subTab={tab} onSubTab={(t) => setTab(t)} />
        )}
        {tab === 'search' && <SearchTab />}
      </div>

      <ConfigJobStreamModal
        isOpen={captureJob != null}
        onClose={() => setCaptureJob(null)}
        jobId={captureJob}
        wsPath="config-capture"
        title="Capture Running Config"
      />
      <ConfigJobStreamModal
        isOpen={revertJob != null}
        onClose={() => setRevertJob(null)}
        jobId={revertJob}
        wsPath="config-revert"
        title="Revert Device to Baseline"
      />
    </div>
  );
}
