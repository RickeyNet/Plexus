import { describe, expect, it } from 'vitest';

import type { TopologyEdge, TopologyNode } from '@/api/topology';

import { edgeProtocolLabel, providerLabel, providerScopeName, providerSourceName } from './helpers';

function ftd(id: string, site: string, provider = 'fmc'): TopologyNode {
  return {
    id,
    label: id,
    in_inventory: false,
    source: 'meraki',
    meraki: { org_ref: 1, node_id: id, site_id: site, site_name: site, kind: 'appliance', status: 'online', provider },
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

describe('Palo Alto Panorama names', () => {
  it('labels the panorama provider everywhere', () => {
    expect(providerLabel('panorama')).toBe('Palo Alto Panorama');
    expect(providerSourceName('panorama')).toBe('Panorama API');
    expect(providerScopeName('panorama')).toBe('Panorama');
  });
});

describe('Appgate SDP names', () => {
  it('labels the appgate provider everywhere', () => {
    expect(providerLabel('appgate')).toBe('Appgate SDP');
    expect(providerSourceName('appgate')).toBe('Appgate SDP API');
    expect(providerScopeName('appgate')).toBe('Appgate collective');
  });
});

describe('GCP names', () => {
  it('labels the gcp provider everywhere', () => {
    expect(providerLabel('gcp')).toBe('GCP');
    expect(providerSourceName('gcp')).toBe('GCP API');
    expect(providerScopeName('gcp')).toBe('GCP project');
  });
});

describe('edgeProtocolLabel', () => {
  it('names an FMC stack link after the HA pair or cluster it joins', () => {
    expect(edgeProtocolLabel(link('stack', 'fmc'), ftd('a', 'ha:1'), ftd('b', 'ha:1'))).toBe('HA');
    expect(edgeProtocolLabel(link('stack', 'fmc'), ftd('a', 'cluster:7'), ftd('b', 'cluster:7'))).toBe('CLUSTER');
    expect(edgeProtocolLabel(link('stack', 'fmc'))).toBe('HA / CLUSTER');
  });

  it('names a Panorama stack link after the HA pair it joins', () => {
    const pa = (id: string) => ftd(id, 'ha:fw-pair', 'panorama');
    expect(edgeProtocolLabel(link('stack', 'panorama'), pa('a'), pa('b'))).toBe('HA');
    expect(edgeProtocolLabel(link('stack', 'panorama'))).toBe('HA / CLUSTER');
  });

  it('keeps the protocol for every other link', () => {
    expect(edgeProtocolLabel(link('stack', 'meraki'))).toBe('STACK');
    expect(edgeProtocolLabel(link('vpn-ipsec', 'fmc'))).toBe('VPN-IPSEC');
    expect(edgeProtocolLabel(link('vpn-ipsec', 'panorama'))).toBe('VPN-IPSEC');
    expect(edgeProtocolLabel({ id: 'e', from: 'a', to: 'b' })).toBe('L2');
  });
});
