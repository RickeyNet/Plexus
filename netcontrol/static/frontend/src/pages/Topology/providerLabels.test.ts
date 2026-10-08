import { describe, expect, it } from 'vitest';

import type { TopologyEdge, TopologyNode } from '@/api/topology';

import { edgeProtocolLabel, providerLabel, providerScopeName, providerSourceName } from './helpers';

function ftd(id: string, site: string): TopologyNode {
  return {
    id,
    label: id,
    in_inventory: false,
    source: 'meraki',
    meraki: { org_ref: 1, node_id: id, site_id: site, site_name: site, kind: 'appliance', status: 'online', provider: 'fmc' },
  };
}

function link(protocol: string, provider?: string): TopologyEdge {
  return { id: 'e', from: 'a', to: 'b', protocol, source: 'meraki', provider };
}

describe('Cisco FMC names', () => {
  it('labels the fmc provider everywhere', () => {
    expect(providerLabel('fmc')).toBe('Cisco FMC');
    expect(providerSourceName('fmc')).toBe('FMC API');
    expect(providerScopeName('fmc')).toBe('Cisco FMC');
  });
});

describe('edgeProtocolLabel', () => {
  it('names an FMC stack link after the HA pair or cluster it joins', () => {
    expect(edgeProtocolLabel(link('stack', 'fmc'), ftd('a', 'ha:1'), ftd('b', 'ha:1'))).toBe('HA');
    expect(edgeProtocolLabel(link('stack', 'fmc'), ftd('a', 'cluster:7'), ftd('b', 'cluster:7'))).toBe('CLUSTER');
    expect(edgeProtocolLabel(link('stack', 'fmc'))).toBe('HA / CLUSTER');
  });

  it('keeps the protocol for every other link', () => {
    expect(edgeProtocolLabel(link('stack', 'meraki'))).toBe('STACK');
    expect(edgeProtocolLabel(link('vpn-ipsec', 'fmc'))).toBe('VPN-IPSEC');
    expect(edgeProtocolLabel({ id: 'e', from: 'a', to: 'b' })).toBe('L2');
  });
});
