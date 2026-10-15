import { TabBar } from '@/components/TabBar';
import { usePathTab } from '@/lib/usePathTab';

import { Reachability } from './Reachability';
import { Topology } from './Topology';

const TAB_KEYS = ['map', 'reachability'] as const;
type TopologyTab = (typeof TAB_KEYS)[number];

const TABS = [
  { key: 'map', label: 'Map' },
  { key: 'reachability', label: 'Reachability' },
] as const satisfies readonly { key: TopologyTab; label: string }[];

/**
 * The Topology page: the map (`/topology`) and the reachability sweep
 * (`/topology/reachability`), one tab each.
 */
export function TopologyPage() {
  const [tab, selectTab] = usePathTab<TopologyTab>('/topology', TAB_KEYS, 'map');
  return (
    <>
      <TabBar tabs={TABS} active={tab} onChange={selectTab} aria-label="Topology views" />
      {tab === 'map' ? <Topology /> : <Reachability />}
    </>
  );
}
