import { PageHeader } from '@/components/PageHeader';
import { TabBar } from '@/components/TabBar';
import { usePathTab } from '@/lib/usePathTab';

import { CablesTab } from './CablesTab';
import { ModulesTab, PortsTab } from './PortsTab';
import { PowerTab } from './PowerTab';
import { RacksTab } from './RacksTab';

const TABS = [
  { key: 'racks', label: 'Racks' },
  { key: 'cables', label: 'Cables' },
  { key: 'patch-panels', label: 'Patch panels' },
  { key: 'power', label: 'Power' },
  { key: 'modules', label: 'Modules' },
] as const;
type DcimTab = (typeof TABS)[number]['key'];
const TAB_KEYS: readonly DcimTab[] = TABS.map((t) => t.key);

/** The DCIM page: racks and their elevations, cables with traces, patch panel ports, power and modules. */
export function Dcim() {
  const [tab, selectTab] = usePathTab<DcimTab>('/dcim', TAB_KEYS, 'racks');
  return (
    <div>
      <PageHeader title="DCIM" />
      <TabBar tabs={TABS} active={tab} onChange={selectTab} aria-label="DCIM sections" />
      {tab === 'racks' && <RacksTab />}
      {tab === 'cables' && <CablesTab />}
      {tab === 'patch-panels' && <PortsTab />}
      {tab === 'power' && <PowerTab />}
      {tab === 'modules' && <ModulesTab />}
    </div>
  );
}
