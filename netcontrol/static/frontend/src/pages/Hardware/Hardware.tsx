import { PageHeader } from '@/components/PageHeader';
import { PageHelp } from '@/components/PageHelp';
import { TabBar } from '@/components/TabBar';
import { usePathTab } from '@/lib/usePathTab';

import { ChangesTab } from './ChangesTab';
import { ComponentsTab } from './ComponentsTab';

const TABS = [
  { key: 'components', label: 'Components' },
  { key: 'changes', label: 'Changes' },
] as const;
type HardwareTab = (typeof TABS)[number]['key'];
const TAB_KEYS: readonly HardwareTab[] = TABS.map((t) => t.key);

/**
 * The Hardware page: every hardware component across the fleet with its
 * serial, and the fleet-wide feed of hardware changes (modules installed,
 * removed, moved or replaced).
 */
export function Hardware() {
  const [tab, selectTab] = usePathTab<HardwareTab>('/hardware', TAB_KEYS, 'components');
  return (
    <div>
      <PageHeader title="Hardware" />
      <PageHelp
        pageKey="hardware"
        title="Hardware Components"
        text="The chassis, modules, power supplies, fans and transceivers of every device, each with its serial, read by SNMP every 6 hours and after a module or restart event. Changes lists every module installed, removed, moved or replaced, and every firmware or revision change, newest first."
      />
      <TabBar tabs={TABS} active={tab} onChange={selectTab} aria-label="Hardware sections" />
      {tab === 'components' && <ComponentsTab />}
      {tab === 'changes' && <ChangesTab />}
    </div>
  );
}
