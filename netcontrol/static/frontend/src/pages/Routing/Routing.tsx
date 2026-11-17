import { PageHeader } from '@/components/PageHeader';
import { PageHelp } from '@/components/PageHelp';
import { TabBar } from '@/components/TabBar';
import { usePathTab } from '@/lib/usePathTab';

import { AutonomousSystemsTab } from './AutonomousSystemsTab';
import { ComplianceTab } from './ComplianceTab';
import { InstancesTab } from './InstancesTab';
import { PeeringsTab } from './PeeringsTab';

const TABS = [
  { key: 'autonomous-systems', label: 'Autonomous systems' },
  { key: 'instances', label: 'Routing instances' },
  { key: 'peerings', label: 'BGP peerings' },
  { key: 'compliance', label: 'Compliance' },
] as const;
type RoutingTab = (typeof TABS)[number]['key'];
const TAB_KEYS: readonly RoutingTab[] = TABS.map((t) => t.key);

/** The Routing page: the intended BGP state of devices and its comparison with what Plexus observes. */
export function Routing() {
  const [tab, selectTab] = usePathTab<RoutingTab>('/routing', TAB_KEYS, 'autonomous-systems');
  return (
    <div>
      <PageHeader title="Routing" />
      <PageHelp
        guide="Routing-and-BGP-Intent"
        pageKey="routing"
        title="Intended BGP state"
        text="Record the autonomous systems, routing instances and BGP peerings each device should have, then compare them with the BGP neighbors neighbor discovery finds."
      />
      <TabBar tabs={TABS} active={tab} onChange={selectTab} aria-label="Routing sections" />
      {tab === 'autonomous-systems' && <AutonomousSystemsTab />}
      {tab === 'instances' && <InstancesTab />}
      {tab === 'peerings' && <PeeringsTab />}
      {tab === 'compliance' && <ComplianceTab />}
    </div>
  );
}
