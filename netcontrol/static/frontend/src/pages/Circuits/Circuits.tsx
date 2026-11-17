import { PageHeader } from '@/components/PageHeader';
import { TabBar } from '@/components/TabBar';
import { usePathTab } from '@/lib/usePathTab';

import { CircuitsTab } from './CircuitsTab';
import { CircuitTypesTab } from './CircuitTypesTab';
import { ProvidersTab } from './ProvidersTab';

const TABS = [
  { key: 'circuits', label: 'Circuits' },
  { key: 'providers', label: 'Providers' },
  { key: 'types', label: 'Circuit types' },
] as const;
type CircuitsPageTab = (typeof TABS)[number]['key'];
const TAB_KEYS: readonly CircuitsPageTab[] = TABS.map((t) => t.key);

/** The Circuits page: circuits with their terminations, providers (with their networks) and circuit types. */
export function Circuits() {
  const [tab, selectTab] = usePathTab<CircuitsPageTab>('/circuits', TAB_KEYS, 'circuits');
  return (
    <div>
      <PageHeader title="Circuits" />
      <TabBar tabs={TABS} active={tab} onChange={selectTab} aria-label="Circuit sections" />
      {tab === 'circuits' && <CircuitsTab />}
      {tab === 'providers' && <ProvidersTab />}
      {tab === 'types' && <CircuitTypesTab />}
    </div>
  );
}
