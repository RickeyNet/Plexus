import { useState } from 'react';

import { useAuthStatus } from '@/api/auth';
import { PageHelp } from '@/components/PageHelp';
import { TabBar } from '@/components/TabBar';
import { visibleTabs } from '@/lib/tabGating';
import { usePathTab } from '@/lib/usePathTab';

import { BackupsTab } from './BackupsTab';
import { DriftTab } from './DriftTab';
import { SearchTab } from './SearchTab';
import { ConfigJobStreamModal } from './ConfigJobStreamModal';

type Tab = 'drift' | 'backups' | 'search';

// Each tab is gated on the feature its API needs: drift on `config-drift`,
// backups and config search (served by the config-backups router) on
// `config-backups`. The sidebar entry shows for either feature.
const TABS: { key: Tab; label: string; feature: string }[] = [
  { key: 'drift', label: 'Config Drift', feature: 'config-drift' },
  { key: 'backups', label: 'Backups', feature: 'config-backups' },
  { key: 'search', label: 'Config Search', feature: 'config-backups' },
];
const TAB_KEYS = TABS.map((t) => t.key);

const TAB_HELP: Record<Tab, { title: string; text: string }> = {
  drift: {
    title: 'Detect & Revert Configuration Drift',
    text: 'Capture a known-good baseline per device, then watch for unexpected changes against it. Diff drift events, revert to baseline, or accept the new config as the new baseline.',
  },
  backups: {
    title: 'Config Backups',
    text: 'Policies define which devices get backed up, how often, and how long backups are retained. History lets you browse captured configs, diff any two versions, and restore a device to a prior state.',
  },
  search: {
    title: 'Search Across All Configs',
    text: 'Full-text search the latest configs of every device - find which switches use a deprecated SNMP community, who still has Telnet enabled, etc.',
  },
};

export function Configuration() {
  const { data: auth } = useAuthStatus();
  const shownTabs = visibleTabs(TABS, auth);
  const [shownTab, selectTab] = usePathTab(
    '/configuration',
    TAB_KEYS,
    'drift',
    auth ? shownTabs.map((t) => t.key) : undefined,
  );
  const [captureJob, setCaptureJob] = useState<string | null>(null);
  const [revertJob, setRevertJob] = useState<string | null>(null);

  const tabHelp = TAB_HELP[shownTab];

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

      {shownTabs.length > 1 && (
        <TabBar tabs={shownTabs} active={shownTab} onChange={selectTab} aria-label="Configuration sections" />
      )}

      <PageHelp pageKey={`configuration.${shownTab}`} title={tabHelp.title} text={tabHelp.text} />

      <div className="card" style={{ padding: '1rem' }}>
        {shownTab === 'drift' && (
          <DriftTab
            onCaptureStarted={(jobId) => setCaptureJob(jobId)}
            onRevertStarted={(jobId) => setRevertJob(jobId)}
          />
        )}
        {shownTab === 'backups' && <BackupsTab />}
        {shownTab === 'search' && <SearchTab />}
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
