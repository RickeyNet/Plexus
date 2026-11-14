import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { Vlan, VlanDetail } from '@/api/networkObjects';

import { VlanDetailPanel, VlansTab } from './VlansTab';

const state = vi.hoisted(() => ({
  vlans: {} as Record<string, unknown>,
  vlan: {} as Record<string, unknown>,
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

vi.mock('@/api/networkObjects', () => ({
  useVlans: () => state.vlans,
  useVlan: () => state.vlan,
  useDeleteVlan: () => mutation,
  useCreateVlan: () => mutation,
  useUpdateVlan: () => mutation,
}));
vi.mock('@/api/floorPlan', () => ({
  useGeoSites: () => ({ data: [{ id: 3, name: 'Branch 1' }] }),
}));
vi.mock('@/api/auth', () => ({ useAuthStatus: () => ({ data: { role: state.role } }) }));
vi.mock('@/components/DialogProvider-context', () => ({
  useDialogs: () => ({ confirm: async () => true, alert: async () => {} }),
}));

const USERS: Vlan = {
  id: 4,
  vid: 10,
  name: 'Users',
  site_id: 3,
  site: { id: 3, name: 'Branch 1' },
  description: 'Office floor',
  origin: 'manual',
  created_at: '2026-01-01 00:00:00',
  device_count: 2,
  interface_count: 24,
  prefix_count: 1,
  name_mismatch: true,
};

describe('VlansTab', () => {
  beforeEach(() => {
    state.role = 'admin';
    state.vlan = query({ isPending: true });
  });

  it('shows loading while the list loads', () => {
    state.vlans = query({ isPending: true });
    expect(renderToStaticMarkup(<VlansTab />)).toContain('Loading VLANs…');
  });

  it('shows the failure with a retry', () => {
    state.vlans = query({ isError: true, error: new Error('403 Forbidden') });
    const html = renderToStaticMarkup(<VlansTab />);
    expect(html).toContain('Failed to load VLANs');
    expect(html).toContain('Retry');
  });

  it('offers Add VLAN on an empty list to admins only', () => {
    state.vlans = query({ data: [] });
    expect(renderToStaticMarkup(<VlansTab />)).toContain('Add VLAN');
    state.role = 'user';
    const html = renderToStaticMarkup(<VlansTab />);
    expect(html).toContain('No VLANs yet.');
    expect(html).not.toContain('Add VLAN');
  });

  it('has a labelled site filter with all, no site and each site', () => {
    state.vlans = query({ data: [] });
    const html = renderToStaticMarkup(<VlansTab />);
    expect(html).toMatch(/<label[^>]*for="([^"]+)-site"[^>]*>Site<select id="\1-site"/);
    expect(html).toContain('<option value="all" selected="">All sites</option>');
    expect(html).toContain('<option value="none">No site (global)</option>');
    expect(html).toContain('<option value="3">Branch 1</option>');
  });

  it('lists the VLANs with the name mismatch marker', () => {
    state.vlans = query({ data: [USERS, { ...USERS, id: 5, vid: 20, name: '', site_id: null, site: null, name_mismatch: false }] });
    const html = renderToStaticMarkup(<VlansTab />);
    for (const text of ['Users', 'Name differs', 'Branch 1', 'Global', 'Office floor', 'aria-label="Edit VLAN 10"', 'aria-label="Delete VLAN 20"']) {
      expect(html).toContain(text);
    }
    expect(html.match(/Name differs/g)).toHaveLength(1);
  });
});

describe('VlanDetailPanel', () => {
  it('asks for a selection when none is made', () => {
    expect(renderToStaticMarkup(<VlanDetailPanel id={null} />)).toContain('Select a VLAN');
  });

  it('shows the failure of the detail request', () => {
    state.vlan = query({ isError: true, error: new Error('404 Not Found') });
    expect(renderToStaticMarkup(<VlanDetailPanel id={4} />)).toContain('Failed to load VLAN details');
  });

  it('shows empty lists as short lines', () => {
    const detail: VlanDetail = { ...USERS, devices: [], interfaces: [], prefixes: [] };
    state.vlan = query({ data: detail });
    const html = renderToStaticMarkup(<VlanDetailPanel id={4} />);
    expect(html).toContain('No device carries this VLAN.');
    expect(html).toContain('No port is in this VLAN.');
  });

  it('lists devices with their own names, ports and prefixes', () => {
    const detail: VlanDetail = {
      ...USERS,
      devices: [
        { host_id: 9, hostname: 'access-1', name: 'Users', state: 'active', name_matches: true },
        { host_id: 10, hostname: 'access-2', name: 'Staff', state: 'active', name_matches: false },
      ],
      interfaces: [{ host_id: 9, hostname: 'access-1', interface: 'Gi1/0/1', mode: 'access' }],
      prefixes: [
        { network: '203.0.113.0/24', vrf_name: '', host_id: 9, hostname: 'access-1', interface: 'Vlan10', address: '203.0.113.1' },
      ],
      truncated: false,
    };
    state.vlan = query({ data: detail });
    const html = renderToStaticMarkup(<VlanDetailPanel id={4} />);
    for (const text of ['VLAN 10 Users', 'access-2', 'Staff', 'Gi1/0/1', 'Access', '203.0.113.0/24', 'Global']) {
      expect(html).toContain(text);
    }
    expect(html.match(/>Differs</g)).toHaveLength(1);
    expect(html).not.toContain('more exist');
  });
});
