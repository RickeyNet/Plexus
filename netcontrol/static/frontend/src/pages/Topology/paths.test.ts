import { describe, expect, it } from 'vitest';

import type { MerakiSubnet } from '@/api/meraki';
import type { TopologyEdge, TopologyNode } from '@/api/topology';

import { connectEndpoints, connectPicks, findSubnets, isAddressText, pathSites, subnetOptionLabel, type PathPick } from './paths';

function meraki(id: string, site: string, kind: string): TopologyNode {
  return {
    id,
    label: id,
    in_inventory: false,
    source: 'meraki',
    meraki: { org_ref: 1, node_id: id, site_id: site, site_name: `Site ${site}`, kind, status: 'online' },
  };
}

function edge(id: string, from: string, to: string, protocol: string, status = ''): TopologyEdge {
  return { id, from, to, protocol, status };
}

// Two spokes and a hub; each spoke also reaches a third-party VPN peer.
const EDGES = [
  edge('lan-a', 'ap-a', 'mx-a', 'lldp'),
  edge('lan-b', 'sw-b', 'mx-b', 'lldp'),
  edge('vpn-a', 'mx-a', 'hub', 'vpn'),
  edge('vpn-b', 'mx-b', 'hub', 'vpn'),
  edge('ipsec-a', 'mx-a', 'peer', 'vpn-ipsec'),
  edge('ipsec-b', 'mx-b', 'peer', 'vpn-ipsec'),
];

describe('path mode', () => {
  it('lists Meraki sites with their appliance as the gateway', () => {
    const sites = pathSites([
      meraki('ap-a', 'A', 'wireless'),
      meraki('mx-a', 'A', 'appliance'),
      meraki('wan-a', 'A', 'wan'),
      meraki('sw-b', 'B', 'switch'),
    ]);
    expect(sites.map((s) => [s.name, s.gateway])).toEqual([
      ['Site A', 'mx-a'],
      ['Site B', 'sw-b'],
    ]);
  });

  it('routes spoke to spoke through the hub rather than a third-party peer', () => {
    const result = connectEndpoints(['ap-a', 'sw-b'], EDGES);
    expect(result.legs[0].path).toEqual(['ap-a', 'mx-a', 'hub', 'mx-b', 'sw-b']);
    expect([...result.edgeIds].sort()).toEqual(['lan-a', 'lan-b', 'vpn-a', 'vpn-b']);
  });

  it('avoids a tunnel that is down', () => {
    const edges = EDGES.map((e) => (e.id === 'vpn-b' ? { ...e, status: 'unreachable' } : e));
    expect(connectEndpoints(['mx-a', 'mx-b'], edges).legs[0].path).toEqual(['mx-a', 'peer', 'mx-b']);
  });

  it('traces every pair and reports the unreachable ones', () => {
    const result = connectEndpoints(['mx-a', 'mx-b', 'island'], EDGES);
    expect(result.legs.map((l) => [l.from, l.to, l.path?.length ?? null])).toEqual([
      ['mx-a', 'mx-b', 3],
      ['mx-a', 'island', null],
      ['mx-b', 'island', null],
    ]);
    expect(result.nodeIds.has('island')).toBe(true);
  });

  function subnet(cidr: string, node: string, site: string, part: Partial<MerakiSubnet> = {}): MerakiSubnet {
    return { org_ref: 1, cidr, name: 'VLAN 10 Data', kind: 'vlan', site_id: site, site_name: `Site ${site}`, node_id: node, in_vpn: true, ...part };
  }

  function pick(s: MerakiSubnet): PathPick {
    return { key: `s:${s.cidr}:${s.node_id}`, node: s.node_id, label: s.cidr, subnet: s };
  }

  it('finds a subnet by picker text, address or network, most specific first', () => {
    const subnets = [
      subnet('10.1.0.0/16', 'mx-a', 'A'),
      subnet('10.1.10.0/24', 'mx-a', 'A'),
      subnet('10.1.10.0/24', 'mx-b', 'B'),
      subnet('10.2.0.0/24', 'mx-b', 'B'),
    ];
    expect(findSubnets(subnetOptionLabel(subnets[2]), subnets)).toEqual([subnets[2]]);
    expect(findSubnets('10.2.0.57', subnets)).toEqual([subnets[3]]);
    expect(findSubnets('10.1.99.0/24', subnets)).toEqual([subnets[0]]);
    // The same subnet at two sites: both come back, the caller has to choose.
    expect(findSubnets(' 10.1.10.20 ', subnets)).toEqual([subnets[1], subnets[2]]);
    expect(findSubnets('192.168.1.1', subnets)).toEqual([]);
    expect(findSubnets('not an address', subnets)).toEqual([]);
    expect([' 10.2.0.57 ', '10.1.0.0/16', 'Site 10', '10.2.0', '300.1.1.1'].map(isAddressText)).toEqual([true, true, false, false, false]);
  });

  it('traces subnets between their owners and treats one device as local', () => {
    const data = pick(subnet('10.1.10.0/24', 'mx-a', 'A'));
    const voice = pick(subnet('10.1.20.0/24', 'mx-a', 'A'));
    const remote = pick(subnet('10.2.10.0/24', 'mx-b', 'B'));
    const result = connectPicks([data, voice, remote], EDGES);
    expect(result.legs.map((l) => [l.sameDevice, l.path, l.notes])).toEqual([
      [true, ['mx-a'], []],
      [false, ['mx-a', 'hub', 'mx-b'], []],
      [false, ['mx-a', 'hub', 'mx-b'], []],
    ]);
  });

  it('warns when the tunnels on the path will not carry a picked subnet', () => {
    const guest = pick(subnet('10.1.30.0/24', 'mx-a', 'A', { in_vpn: false }));
    const remote = pick(subnet('10.2.10.0/24', 'mx-b', 'B'));
    const cloud = pick(subnet('172.31.0.0/16', 'peer', '', { kind: 'peer', in_vpn: null, site_name: '' }));
    const result = connectPicks([guest, remote, cloud], EDGES);
    expect(result.legs[0].notes).toEqual(['10.1.30.0/24 is not advertised into the VPN at Site A, so a tunnel will not carry it.']);
    // Each site has its own tunnel to the peer: nothing to warn about there.
    expect(result.legs[2].path).toEqual(['mx-b', 'peer']);
    expect(result.legs[2].notes).toEqual([]);

    // Without that tunnel the only way is through the hub, which will not work.
    const edges = EDGES.filter((e) => e.id !== 'ipsec-b').concat([edge('ipsec-hub', 'hub', 'peer', 'vpn-ipsec')]);
    const far = connectPicks([remote, cloud], edges).legs[0];
    expect(far.path).toEqual(['mx-b', 'hub', 'peer']);
    expect(far.notes).toHaveLength(1);
    expect(far.notes[0]).toContain('non-Meraki VPN peer');
  });
});

describe('path mode with a Cato account', () => {
  it('offers Cato sites but not the cloud, and routes through the PoPs', () => {
    const nodes = [
      meraki('sock-a', 'A', 'appliance'),
      meraki('sock-b', 'B', 'appliance'),
      meraki('pop-1', 'cloud', 'cloud'),
      meraki('pop-2', 'cloud', 'cloud'),
      meraki('backbone', 'cloud', 'cloud'),
      meraki('users', 'cloud', 'users'),
    ];
    expect(pathSites(nodes).map((s) => s.name)).toEqual(['Site A', 'Site B']);

    const traced = connectEndpoints(['sock-a', 'sock-b'], [
      edge('t-a', 'sock-a', 'pop-1', 'vpn'),
      edge('t-b', 'sock-b', 'pop-2', 'vpn'),
      edge('b-1', 'pop-1', 'backbone', 'vpn'),
      edge('b-2', 'pop-2', 'backbone', 'vpn'),
    ]);
    expect(traced.legs[0].path).toEqual(['sock-a', 'pop-1', 'backbone', 'pop-2', 'sock-b']);
  });

  it('does not route through a site whose tunnel is down', () => {
    const traced = connectEndpoints(['sock-a', 'sock-b'], [
      edge('t-a', 'sock-a', 'pop-1', 'vpn'),
      edge('t-b', 'sock-b', 'backbone', 'vpn', 'unreachable'),
      edge('b-1', 'pop-1', 'backbone', 'vpn'),
    ]);
    expect(traced.legs[0].path).toBeNull();
  });
});

describe('path mode with AWS', () => {
  it('offers each VPC with its router as the gateway, not the firewall inside it', () => {
    const nodes = [
      meraki('ftd', 'edge', 'appliance'),
      meraki('vpc-edge', 'edge', 'vpc'),
      meraki('igw', 'edge', 'wan'),
      meraki('vpc-core', 'core', 'vpc'),
      meraki('tgw', 'transit', 'cloud'),
      meraki('cgw', 'transit', 'vpn_peer'),
    ];
    expect(pathSites(nodes).map((s) => [s.name, s.gateway])).toEqual([
      ['Site core', 'vpc-core'],
      ['Site edge', 'vpc-edge'],
    ]);
  });

  it('routes between VPCs over the transit gateway and skips a failed attachment', () => {
    const attached = [
      edge('a-core', 'vpc-core', 'tgw', 'cloud', 'active'),
      edge('a-edge', 'vpc-edge', 'tgw', 'cloud', 'active'),
    ];
    expect(connectEndpoints(['vpc-core', 'vpc-edge'], attached).legs[0].path).toEqual(['vpc-core', 'tgw', 'vpc-edge']);
    const broken = [attached[0], edge('a-edge', 'vpc-edge', 'tgw', 'cloud', 'failed')];
    expect(connectEndpoints(['vpc-core', 'vpc-edge'], broken).legs[0].path).toBeNull();
  });
});
