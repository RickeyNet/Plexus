import { describe, expect, it } from 'vitest';

import {
  addressRoleLabel,
  describeCarriers,
  formatInterfaceAddress,
  hostNetworkBody,
  interfacesByAddress,
  parseVid,
  siteFilterFromSelect,
  siteFilterToSelect,
  vlanListPath,
  vrfLabel,
} from './networkObjects';

describe('vlanListPath', () => {
  it('adds only the filters that narrow the list', () => {
    expect(vlanListPath('all')).toBe('/ipam/vlans');
    expect(vlanListPath('none')).toBe('/ipam/vlans?site_id=none');
    expect(vlanListPath(3)).toBe('/ipam/vlans?site_id=3');
    expect(vlanListPath(3, 10)).toBe('/ipam/vlans?site_id=3&vid=10');
    expect(vlanListPath('all', 10)).toBe('/ipam/vlans?vid=10');
  });
});

describe('site filter select values', () => {
  it('round-trips every choice', () => {
    for (const site of ['all', 'none', 7] as const) {
      expect(siteFilterFromSelect(siteFilterToSelect(site))).toBe(site);
    }
  });

  it('reads anything unknown as all', () => {
    expect(siteFilterFromSelect('')).toBe('all');
    expect(siteFilterFromSelect('x')).toBe('all');
    expect(siteFilterFromSelect('-2')).toBe('all');
    expect(siteFilterFromSelect('1.5')).toBe('all');
  });
});

describe('parseVid', () => {
  it('takes whole numbers from 1 to 4094', () => {
    expect(parseVid('1')).toBe(1);
    expect(parseVid(' 4094 ')).toBe(4094);
    expect(parseVid('100')).toBe(100);
  });

  it('rejects anything else', () => {
    for (const text of ['', '0', '4095', '-1', '10.5', '1e3', 'ten', '10 20']) {
      expect(parseVid(text)).toBeNull();
    }
  });
});

describe('address formatting', () => {
  it('writes the address with its prefix length', () => {
    expect(formatInterfaceAddress({ address: '192.0.2.1', prefix_length: 24 })).toBe('192.0.2.1/24');
    expect(formatInterfaceAddress({ address: '2001:db8::1', prefix_length: 64 })).toBe('2001:db8::1/64');
  });

  it('names the role and the protocol of a virtual address', () => {
    expect(addressRoleLabel({ role: 'primary', protocol: '' })).toBe('Primary');
    expect(addressRoleLabel({ role: 'secondary', protocol: '' })).toBe('Secondary');
    expect(addressRoleLabel({ role: 'virtual', protocol: 'HSRP' })).toBe('Virtual (HSRP)');
    expect(addressRoleLabel({ role: '', protocol: '' })).toBe('Unknown');
  });

  it('calls the empty VRF Global', () => {
    expect(vrfLabel('')).toBe('Global');
    expect(vrfLabel(null)).toBe('Global');
    expect(vrfLabel('BLUE')).toBe('BLUE');
  });
});

describe('interfacesByAddress / describeCarriers', () => {
  const rows = [
    { address: '192.0.2.1', hostname: 'edge-1', interface: 'Vlan10' },
    { address: '192.0.2.2', hostname: 'edge-2', interface: 'Vlan10' },
    { address: '192.0.2.1', hostname: 'edge-2', interface: 'Vlan10' },
  ];

  it('groups the rows by address in order', () => {
    const map = interfacesByAddress(rows);
    expect([...map.keys()]).toEqual(['192.0.2.1', '192.0.2.2']);
    expect(map.get('192.0.2.1')?.map((r) => r.hostname)).toEqual(['edge-1', 'edge-2']);
  });

  it('names the first carrier and counts the others', () => {
    expect(describeCarriers([])).toBe('');
    expect(describeCarriers([rows[0]])).toBe('edge-1 Vlan10');
    expect(describeCarriers([rows[0], rows[2]])).toBe('edge-1 Vlan10 and 1 more');
  });
});

describe('hostNetworkBody', () => {
  it('sends the typed values of a new host', () => {
    expect(hostNetworkBody(null, '', '')).toEqual({});
    expect(hostNetworkBody(null, ' BLUE ', '')).toEqual({ vrf_name: 'BLUE' });
    expect(hostNetworkBody(null, 'BLUE', '10')).toEqual({ vrf_name: 'BLUE', vlan_id: '10' });
  });

  it('sends nothing when an edit leaves both values', () => {
    expect(hostNetworkBody({ vrf_name: 'BLUE', vlan_id: '10' }, 'BLUE', '10')).toEqual({});
    expect(hostNetworkBody({ vrf_name: null, vlan_id: null }, '', '')).toEqual({});
    expect(hostNetworkBody({}, '', '')).toEqual({});
  });

  it('sends both known values when one changes, so clearing works', () => {
    expect(hostNetworkBody({ vrf_name: 'BLUE', vlan_id: '10' }, 'RED', '10')).toEqual({ vrf_name: 'RED', vlan_id: '10' });
    expect(hostNetworkBody({ vrf_name: 'BLUE', vlan_id: '10' }, '', '10')).toEqual({ vrf_name: '', vlan_id: '10' });
    expect(hostNetworkBody({ vrf_name: 'BLUE', vlan_id: 10 }, 'BLUE', '20')).toEqual({ vrf_name: 'BLUE', vlan_id: '20' });
  });

  it('sends only what was typed when the row does not carry the values', () => {
    expect(hostNetworkBody({}, 'BLUE', '')).toEqual({ vrf_name: 'BLUE' });
    expect(hostNetworkBody({}, '', '30')).toEqual({ vlan_id: '30' });
  });
});
