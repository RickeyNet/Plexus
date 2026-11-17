import { useState } from 'react';

import { PageHeader } from '@/components/PageHeader';
import { TabBar } from '@/components/TabBar';
import { usePathTab } from '@/lib/usePathTab';

import { ConnectionsTab } from './ConnectionsTab';
import { JobsTab } from './JobsTab';
import { RunDetailModal } from './RunDetailModal';
import { RunsTab } from './RunsTab';

const TABS = [
  { key: 'jobs', label: 'Jobs' },
  { key: 'runs', label: 'Run history' },
  { key: 'connections', label: 'Connections' },
] as const;
type SyncPageTab = (typeof TABS)[number]['key'];
const TAB_KEYS: readonly SyncPageTab[] = TABS.map((t) => t.key);

/**
 * The Sync page: jobs that sync Plexus with NetBox, Nautobot or ServiceNow
 * (dry run, run now), their run history with a per-object diff, and the
 * connections the jobs use.
 */
export function Sync() {
  const [tab, selectTab] = usePathTab<SyncPageTab>('/sync', TAB_KEYS, 'jobs');
  const [openRun, setOpenRun] = useState<number | null>(null);
  return (
    <div>
      <PageHeader title="Sync" />
      <TabBar tabs={TABS} active={tab} onChange={selectTab} aria-label="Sync sections" />
      {tab === 'jobs' && <JobsTab onOpenRun={setOpenRun} />}
      {tab === 'runs' && <RunsTab onOpenRun={setOpenRun} />}
      {tab === 'connections' && <ConnectionsTab />}
      {openRun !== null && <RunDetailModal runId={openRun} onClose={() => setOpenRun(null)} />}
    </div>
  );
}
