import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { type HostInterfaceAddresses, NETWORK_OBJECT_KEYS } from '@/api/networkObjects';

import { InterfaceAddressesTable } from './InterfaceAddressesTable';

function render(data: HostInterfaceAddresses): string {
  const qc = new QueryClient();
  qc.setQueryData(NETWORK_OBJECT_KEYS.hostAddresses(7), data);
  return renderToStaticMarkup(
    <QueryClientProvider client={qc}>
      <InterfaceAddressesTable hostId={7} />
    </QueryClientProvider>,
  );
}

const ROW = {
  host_id: 7,
  hostname: 'core-1',
  interface: 'Vlan20',
  address: '198.51.100.1',
  prefix_length: 24,
  network: '198.51.100.0/24',
  vrf_name: '',
  role: 'primary',
  protocol: '',
  svi_vid: 20,
  collected_at: '2026-01-01 00:00:00',
  vrf_id: null,
  vlan_id: 3,
};

describe('InterfaceAddressesTable', () => {
  it('shows a short line, not an error, when the device has no addresses', () => {
    const html = render({ host_id: 7, addresses: [], vrfs: [] });
    expect(html).toContain('IP addresses');
    expect(html).toContain('No interface addresses.');
    expect(html).not.toContain('<table');
  });

  it('lists interface, address, VRF, role and VLAN', () => {
    const html = render({
      host_id: 7,
      addresses: [ROW, { ...ROW, interface: 'Loopback0', address: '192.0.2.9', prefix_length: 32, vrf_name: 'MGMT', svi_vid: 0, vlan_id: null }],
      vrfs: [{ name: 'MGMT', vrf_id: 2, interface_count: 1 }],
    });
    for (const text of ['Vlan20', '198.51.100.1/24', 'Global', 'Primary', '>20<', 'Loopback0', '192.0.2.9/32', 'MGMT']) {
      expect(html).toContain(text);
    }
  });
});
