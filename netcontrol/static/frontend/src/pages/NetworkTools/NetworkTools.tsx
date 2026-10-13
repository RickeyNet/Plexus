import { useAuthStatus } from '@/api/auth';
import { TabBar } from '@/components/TabBar';
import { visibleTabs } from '@/lib/tabGating';
import { usePathTab } from '@/lib/usePathTab';

import { MacTracking } from './MacTracking';
import { TrafficAnalysis } from './TrafficAnalysis';

type Tab = 'mac' | 'traffic';

// One sidebar entry for both tools. The views stay separate components - their
// data is disjoint (MAC/ARP tables vs flow records) - and each tab is gated on
// its own feature. The old standalone paths (/mac-tracking,
// /traffic-analysis) redirect here.
const TABS: { key: Tab; label: string; feature: string }[] = [
  { key: 'mac', label: 'MAC Tracking', feature: 'mac-tracking' },
  { key: 'traffic', label: 'Traffic Analysis', feature: 'traffic-analysis' },
];
const TAB_KEYS = TABS.map((t) => t.key);

export function NetworkTools() {
  const { data: auth } = useAuthStatus();
  const shownTabs = visibleTabs(TABS, auth);
  const [tab, selectTab] = usePathTab(
    '/network-tools',
    TAB_KEYS,
    'mac',
    auth ? shownTabs.map((t) => t.key) : undefined,
  );

  return (
    <div className="page">
      <div className="page-header">
        <h2>Network Tools</h2>
      </div>

      <TabBar tabs={shownTabs} active={tab} onChange={selectTab} aria-label="Network tools" />

      {tab === 'mac' && <MacTracking />}
      {tab === 'traffic' && <TrafficAnalysis />}
    </div>
  );
}
