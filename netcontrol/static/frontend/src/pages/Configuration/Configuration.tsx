import { useState } from 'react';

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

export function Configuration() {
  const [tab, setTab] = useState<Tab>('drift');
  const [captureJob, setCaptureJob] = useState<string | null>(null);
  const [revertJob, setRevertJob] = useState<string | null>(null);

  return (
    <div>
      <div className="page-header" style={{ marginBottom: '0.75rem' }}>
        <h2 style={{ margin: 0 }}>Configuration</h2>
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
