import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { Vrf, VrfDetail } from '@/api/networkObjects';

import { VrfDetailPanel, VrfsTab } from './VrfsTab';

const state = vi.hoisted(() => ({
  vrfs: {} as Record<string, unknown>,
  vrf: {} as Record<string, unknown>,
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
  useVrfs: () => state.vrfs,
  useVrf: () => state.vrf,
  useDeleteVrf: () => mutation,
  useRebuildInterfaceAddresses: () => mutation,
  useCreateVrf: () => mutation,
  useUpdateVrf: () => mutation,
}));
vi.mock('@/api/auth', () => ({ useAuthStatus: () => ({ data: { role: state.role } }) }));
vi.mock('@/components/DialogProvider-context', () => ({
  useDialogs: () => ({ confirm: async () => true, alert: async () => {} }),
}));

const BLUE: Vrf = {
  id: 1,
  name: 'BLUE',
  rd: '65000:100',
  description: 'Branch users',
  origin: 'discovered',
  created_at: '2026-01-01 00:00:00',
  host_count: 2,
  device_count: 3,
  prefix_count: 4,
  address_count: 5,
};

describe('VrfsTab', () => {
  beforeEach(() => {
    state.role = 'admin';
    state.vrf = query({ isPending: true });
  });

  it('shows loading while the list loads', () => {
    state.vrfs = query({ isPending: true });
    expect(renderToStaticMarkup(<VrfsTab />)).toContain('Loading VRFs…');
  });

  it('shows the failure with a retry', () => {
    state.vrfs = query({ isError: true, error: new Error('500 Internal Server Error') });
    const html = renderToStaticMarkup(<VrfsTab />);
    expect(html).toContain('Failed to load VRFs');
    expect(html).toContain('500 Internal Server Error');
    expect(html).toContain('Retry');
  });

  it('offers Add VRF on an empty list to admins only', () => {
    state.vrfs = query({ data: [] });
    const admin = renderToStaticMarkup(<VrfsTab />);
    expect(admin).toContain('No VRFs yet.');
    expect(admin).toContain('Add VRF');
    state.role = 'user';
    const user = renderToStaticMarkup(<VrfsTab />);
    expect(user).toContain('No VRFs yet.');
    expect(user).not.toContain('Add VRF');
    expect(user).not.toContain('Rebuild interface addresses');
  });

  it('lists the VRFs with their counts and row actions', () => {
    state.vrfs = query({ data: [BLUE] });
    const html = renderToStaticMarkup(<VrfsTab />);
    for (const text of ['BLUE', '65000:100', 'Discovered', 'Branch users', 'Add VRF', 'aria-label="Edit VRF BLUE"', 'aria-label="Delete VRF BLUE"']) {
      expect(html).toContain(text);
    }
    expect(html).toMatch(/<tr[^>]*tabindex="0"/);
    expect(html).toContain('Select a VRF to see its devices');
    state.role = 'user';
    expect(renderToStaticMarkup(<VrfsTab />)).not.toContain('Edit VRF BLUE');
  });
});

describe('VrfDetailPanel', () => {
  it('shows the failure of the detail request', () => {
    state.vrf = query({ isError: true, error: new Error('404 Not Found') });
    expect(renderToStaticMarkup(<VrfDetailPanel id={1} />)).toContain('Failed to load VRF details');
  });

  it('shows empty lists as short lines', () => {
    const detail: VrfDetail = { ...BLUE, devices: [], interfaces: [], prefixes: [], truncated: false };
    state.vrf = query({ data: detail });
    const html = renderToStaticMarkup(<VrfDetailPanel id={1} />);
    expect(html).toContain('No device has an interface or route in this VRF.');
    expect(html).toContain('No interface address in this VRF.');
    expect(html).toContain('No prefix in this VRF.');
  });

  it('lists devices, addresses and prefixes, and says when addresses were cut short', () => {
    const detail: VrfDetail = {
      ...BLUE,
      devices: [{ host_id: 9, hostname: 'edge-1', interface_count: 2 }],
      interfaces: [
        {
          host_id: 9,
          hostname: 'edge-1',
          interface: 'Vlan10',
          address: '192.0.2.1',
          prefix_length: 24,
          network: '192.0.2.0/24',
          vrf_name: 'BLUE',
          role: 'virtual',
          protocol: 'HSRP',
          svi_vid: 10,
          collected_at: '2026-01-01 00:00:00',
        },
      ],
      prefixes: [{ subnet: '198.51.100.0/24', source: 'interface' }],
      truncated: true,
    };
    state.vrf = query({ data: detail });
    const html = renderToStaticMarkup(<VrfDetailPanel id={1} />);
    for (const text of ['VRF BLUE', 'edge-1', '192.0.2.1/24', 'Virtual (HSRP)', '198.51.100.0/24', 'Showing the first 1 addresses; more exist.']) {
      expect(html).toContain(text);
    }
  });
});
