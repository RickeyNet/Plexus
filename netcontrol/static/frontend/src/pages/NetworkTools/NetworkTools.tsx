import { useAuthStatus } from '@/api/auth';
import { PageHeader } from '@/components/PageHeader';
import { TabBar } from '@/components/TabBar';
import { visibleTabs } from '@/lib/tabGating';
import { usePathTab } from '@/lib/usePathTab';
import { Reachability } from '@/pages/Topology/Reachability';
import { Summarize } from '@/pages/Topology/Summarize';

import { MacTracking } from './MacTracking';
import { TrafficAnalysis } from './TrafficAnalysis';

type Tab = 'mac' | 'traffic' | 'reachability' | 'summarize';

// One sidebar entry for the network tools. The views stay separate components
// with disjoint data (MAC/ARP tables, flow records, the topology sources) and
// each tab is gated on its own feature. Reachability and Summarize work on the
// topology sources, so they stay under pages/Topology beside the path-trace
// helpers they share with the map. The old paths (/mac-tracking,
// /traffic-analysis, /topology/reachability, /topology/summarize) redirect here.
const TABS: { key: Tab; label: string; feature: string }[] = [
  { key: 'mac', label: 'MAC Tracking', feature: 'mac-tracking' },
  { key: 'traffic', label: 'Traffic Analysis', feature: 'traffic-analysis' },
  { key: 'reachability', label: 'Reachability', feature: 'topology' },
  { key: 'summarize', label: 'Summarize', feature: 'topology' },
];
const TAB_KEYS = TABS.map((t) => t.key);
// Traffic Analysis resolves /network-tools/traffic/<view> with its own usePathTab.
const NESTED: Tab[] = ['traffic'];

export function NetworkTools() {
  const { data: auth } = useAuthStatus();
  const shownTabs = visibleTabs(TABS, auth);
  const [tab, selectTab] = usePathTab(
    '/network-tools',
    TAB_KEYS,
    'mac',
    auth ? shownTabs.map((t) => t.key) : undefined,
    NESTED,
  );

  return (
    <div className="page">
      <PageHeader title="Network Tools" />

      <TabBar tabs={shownTabs} active={tab} onChange={selectTab} aria-label="Network tools" />

      {tab === 'mac' && <MacTracking />}
      {tab === 'traffic' && <TrafficAnalysis />}
      {tab === 'reachability' && <Reachability />}
      {tab === 'summarize' && <Summarize />}
    </div>
  );
}
