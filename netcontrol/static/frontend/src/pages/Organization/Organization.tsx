import { PageHeader } from '@/components/PageHeader';
import { PageHelp } from '@/components/PageHelp';
import { TabBar } from '@/components/TabBar';
import { usePathTab } from '@/lib/usePathTab';

import { RegionsTab } from './RegionsTab';
import { SitesTab } from './SitesTab';
import { TenantGroupsTab, TenantsTab } from './TenantsTab';

type OrganizationTab = 'regions' | 'sites' | 'tenant-groups' | 'tenants';

const TABS: { key: OrganizationTab; label: string }[] = [
  { key: 'regions', label: 'Regions' },
  { key: 'sites', label: 'Sites' },
  { key: 'tenant-groups', label: 'Tenant groups' },
  { key: 'tenants', label: 'Tenants' },
];
const TAB_KEYS = TABS.map((t) => t.key);

/** Organization: the location hierarchy (regions > sites > floors) and tenancy (tenant groups and tenants). */
export function Organization() {
  const [tab, selectTab] = usePathTab<OrganizationTab>('/organization', TAB_KEYS, 'regions');
  return (
    <div>
      <PageHeader title="Organization" />
      <PageHelp
        pageKey="organization"
        title="Locations and tenants"
        text="Regions nest inside each other and hold sites; sites hold floors. Tenants say who a host, site, prefix, IP address, VLAN or VRF belongs to, and tenant groups file them. Filter inventory by region (including the regions under it) or by tenant."
      />
      <TabBar tabs={TABS} active={tab} onChange={selectTab} aria-label="Organization sections" />
      {tab === 'regions' && <RegionsTab />}
      {tab === 'sites' && <SitesTab />}
      {tab === 'tenant-groups' && <TenantGroupsTab />}
      {tab === 'tenants' && <TenantsTab />}
    </div>
  );
}
