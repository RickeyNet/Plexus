import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { AggregatesTab, NamespacesTab, RouteTargetsTab, VlanGroupsTab } from './IpamRecordsTabs';

const state = vi.hoisted(() => ({
  lists: {} as Record<string, unknown[]>,
  detail: undefined as unknown,
  role: 'admin',
}));

const query = (over: Record<string, unknown>) => ({
  isError: false,
  isPending: false,
  isFetching: false,
  data: undefined,
  error: null,
  refetch: () => {},
  ...over,
});
const mutation = { isPending: false, mutate: () => {}, mutateAsync: async () => ({}) };

vi.mock('@/api/dcim', () => ({
  useDcimList: (kind: string) => query({ data: state.lists[kind] ?? [] }),
  useDcimRecord: (_kind: string, id: number | null) =>
    id === null ? query({ isPending: true }) : query({ data: state.detail }),
  useDcimChoices: () => query({ data: {} }),
  useSaveDcimRecord: () => mutation,
  useDeleteDcimRecord: () => mutation,
}));
vi.mock('@/api/auth', () => ({ useAuthStatus: () => ({ data: { role: state.role } }) }));
vi.mock('@/api/floorPlan', () => ({ useGeoSites: () => ({ data: [{ id: 3, name: 'Branch 1' }] }) }));
vi.mock('@/api/organization', () => ({ useRegions: () => ({ data: [{ id: 2, name: 'East' }] }) }));
vi.mock('@/api/inventory', () => ({ useInventoryGroupsFull: () => ({ data: [] }) }));
vi.mock('@/components/DialogProvider-context', () => ({
  useDialogs: () => ({ confirm: async () => true, alert: async () => {} }),
}));

describe('IPAM record tabs', () => {
  beforeEach(() => {
    state.role = 'admin';
    state.lists = {};
    state.detail = undefined;
  });

  it('marks the Global namespace and counts its VRFs and prefixes', () => {
    state.lists.namespace = [
      { id: 1, name: 'Global', description: '', vrf_count: 3, prefix_count: 12 },
      { id: 2, name: 'Lab', description: 'test bed', vrf_count: 0, prefix_count: 1 },
    ];
    const html = renderToStaticMarkup(<NamespacesTab />);
    expect(html).toContain('Global');
    expect(html).toContain('Default');
    expect(html).toContain('test bed');
    expect(html).toContain('Add namespace');
  });

  it('hides the write actions from non-admins', () => {
    state.role = 'user';
    state.lists.route_target = [
      { id: 1, name: '65000:100', import_vrf_count: 2, export_vrf_count: 1, tenant_name: null, description: '' },
    ];
    const html = renderToStaticMarkup(<RouteTargetsTab />);
    expect(html).toContain('65000:100');
    expect(html).toContain('2 VRFs');
    expect(html).not.toContain('Add route target');
    expect(html).not.toContain('Actions');
  });

  it('shows each aggregate with its RIR and utilization, and the RIRs', () => {
    state.lists.aggregate = [
      {
        id: 5,
        prefix: '198.51.100.0/24',
        rir_name: 'RFC 5737',
        prefix_count: 2,
        utilization_pct: 75,
        used_addresses: 192,
        total_addresses: 256,
        date_added: '2026-01-15',
        tenant_name: null,
      },
    ];
    state.lists.rir = [{ id: 1, name: 'RFC 5737', is_private: true, aggregate_count: 1, description: '' }];
    const html = renderToStaticMarkup(<AggregatesTab />);
    expect(html).toContain('198.51.100.0/24');
    expect(html).toContain('75% (192 of 256 addresses)');
    expect(html).toContain('Utilization of 198.51.100.0/24');
    expect(html).toContain('RIRs');
    expect(html).toContain('Yes');
  });

  it('lists VLAN groups with their range and scope', () => {
    state.lists.vlan_group = [
      { id: 7, name: 'Campus', min_vid: 100, max_vid: 199, site_id: 3, site_name: 'Branch 1', region_id: null, vlan_count: 4 },
    ];
    const html = renderToStaticMarkup(<VlanGroupsTab />);
    expect(html).toContain('Campus');
    expect(html).toContain('100-199');
    expect(html).toContain('Site Branch 1');
    expect(html).toContain('Select a VLAN group to see its VLANs and the next free VLAN id.');
  });
});
