import { PageHeader } from '@/components/PageHeader';
import { PageHelp } from '@/components/PageHelp';
import { TabBar } from '@/components/TabBar';
import { usePathTab } from '@/lib/usePathTab';

import { CatalogTab } from './CatalogTab';
import { ClustersTab } from './ClustersTab';
import { VirtualMachinesTab } from './VirtualMachinesTab';

type VirtualizationTab = 'vms' | 'clusters' | 'types' | 'groups';

const TABS: { key: VirtualizationTab; label: string }[] = [
  { key: 'vms', label: 'Virtual machines' },
  { key: 'clusters', label: 'Clusters' },
  { key: 'types', label: 'Cluster types' },
  { key: 'groups', label: 'Cluster groups' },
];
const TAB_KEYS = TABS.map((t) => t.key);

/** Virtualization: virtual machines, clusters with their hypervisors, cluster types and groups. */
export function Virtualization() {
  const [tab, selectTab] = usePathTab<VirtualizationTab>('/virtualization', TAB_KEYS, 'vms');
  return (
    <div>
      <PageHeader title="Virtualization" />
      <PageHelp
        guide="Virtualization"
        pageKey="virtualization"
        title="Clusters and virtual machines"
        text="Model the clusters that run your virtual machines, the hypervisor hosts in each, and every VM with its interfaces and addresses. AWS, Azure and GCP instances found by Cloud Visibility are added and kept current automatically; a VM you edit keeps your values."
      />
      <TabBar tabs={TABS} active={tab} onChange={selectTab} aria-label="Virtualization sections" />
      {tab === 'vms' && <VirtualMachinesTab />}
      {tab === 'clusters' && <ClustersTab />}
      {tab === 'types' && <CatalogTab kind="type" />}
      {tab === 'groups' && <CatalogTab kind="group" />}
    </div>
  );
}
