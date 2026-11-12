import { describe, expect, it } from 'vitest';

import type { MerakiSubnet } from '@/api/meraki';
import type { TopologyEdge, TopologyNode } from '@/api/topology';

import {
  appCandidate,
  appOptions,
  appPick,
  connectEndpoints,
  connectPicks,
  findNamedHosts,
  findSubnets,
  isAddressText,
  parseTraffic,
  pathModeHint,
  pathSites,
  pickEnd,
  subnetOptionLabel,
  suggestHosts,
  subnetPick,
  userPick,
  type PathPick,
} from './paths';

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

  it('picks a subnet at its owner, keeping a typed address narrower than the subnet', () => {
    const vlan = subnet('10.74.0.0/16', 'mx-hq', 'HQ', { name: 'Static route 10.74_Summary', kind: 'static' });
    expect(subnetPick(vlan, 'node-hq', ' 10.74.76.10 ')).toEqual({
      key: 's:1:10.74.76.10:mx-hq',
      node: 'node-hq',
      label: '10.74.76.10 · Site HQ',
      subnet: vlan,
      address: '10.74.76.10',
    });
    // The subnet itself, or its picker text, picks the whole subnet.
    for (const typed of ['10.74.0.0/16', subnetOptionLabel(vlan)]) {
      const whole = subnetPick(vlan, 'node-hq', typed);
      expect([whole.key, whole.label, whole.address]).toEqual(['s:1:10.74.0.0/16:mx-hq', '10.74.0.0/16 · Site HQ', undefined]);
    }
    expect(subnetPick({ ...vlan, site_name: '' }, 'node-hq', '10.74.76.10').label).toBe('10.74.76.10 · Static route 10.74_Summary');
  });

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
    // A DNS name, or a URL, mount or host:port of it, finds every address of its host.
    const hosts = [
      subnet('192.0.2.10/32', 'vpc:1', '1', { kind: 'host', name: 'FSx files', dns_names: ['files.example.com'] }),
      subnet('192.0.2.11/32', 'vpc:1', '1', { kind: 'host', name: 'FSx files', dns_names: ['files.example.com', 'smb.example.com'] }),
      subnet('192.0.2.20/32', 'vpc:1', '1', { kind: 'host', name: 'RDS db', dns_names: ['db.example.com'] }),
    ];
    const all = [...subnets, ...hosts];
    for (const typed of ['files.example.com', ' Files.Example.com. ', 'https://files.example.com/share', '\\\\files.example.com\\share', 'files.example.com:/fsx', 'files.example.com:445']) {
      expect(findNamedHosts(typed, all), typed).toEqual([hosts[0], hosts[1]]);
    }
    expect(findNamedHosts('smb.example.com', all)).toEqual([hosts[1]]);
    // Not part of a name, and not an address: those are findSubnets' to place.
    expect(findNamedHosts('example.com', all)).toEqual([]);
    expect(findNamedHosts('192.0.2.10', all)).toEqual([]);
    expect(findNamedHosts('', all)).toEqual([]);
    // While a name is typed, the hosts it is part of are offered, a name that starts with it first.
    expect(suggestHosts('fil', all)).toEqual([
      { host: hosts[0], dnsName: 'files.example.com' },
      { host: hosts[1], dnsName: 'files.example.com' },
    ]);
    expect(suggestHosts('https://smb.exa', all)).toEqual([{ host: hosts[1], dnsName: 'smb.example.com' }]);
    expect(suggestHosts('example', all).map((s) => s.host)).toEqual(hosts);
    expect(suggestHosts('example', all, 2)).toHaveLength(2);
    // The resource's own name finds it too, with its first DNS name shown.
    expect(suggestHosts('rds', all)).toEqual([{ host: hosts[2], dnsName: 'db.example.com' }]);
    expect(suggestHosts('B.EXAMPLE', all)).toEqual([
      { host: hosts[1], dnsName: 'smb.example.com' },
      { host: hosts[2], dnsName: 'db.example.com' },
    ]);
    // Nothing for one character, an address being typed, a subnet's name or an entry already spelled out.
    for (const typed of ['f', '192.0.2', '192.0.2.10/32', 'VLAN 10', subnetOptionLabel(hosts[0])]) {
      expect(suggestHosts(typed, all), typed).toEqual([]);
    }
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
    // Each leg knows the links it runs over, so a trace can replace it on the map.
    expect(result.legs.map((l) => [...l.edgeIds].sort())).toEqual([[], ['vpn-a', 'vpn-b'], ['vpn-a', 'vpn-b']]);
  });

  it('warns when the tunnels on the path will not carry a picked subnet', () => {
    const guest = pick(subnet('10.1.30.0/24', 'mx-a', 'A', { in_vpn: false }));
    const remote = pick(subnet('10.2.10.0/24', 'mx-b', 'B'));
    const cloud = pick(subnet('172.21.0.0/16', 'peer', '', { kind: 'peer', in_vpn: null, site_name: '' }));
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

describe('path mode with a Cisco FMC', () => {
  it('offers each FTD as a site, but neither the FMC nor the users node', () => {
    const nodes = [
      meraki('ftd-1', 'dev:1', 'appliance'),
      meraki('wan-1', 'dev:1', 'wan'),
      meraki('users-1', 'dev:1', 'users'),
      meraki('ftd-2', 'dev:2', 'appliance'),
      meraki('fmc', 'fmc', 'cloud'),
    ];
    expect(pathSites(nodes).map((s) => [s.name, s.gateway])).toEqual([
      ['Site dev:1', 'ftd-1'],
      ['Site dev:2', 'ftd-2'],
    ]);
  });

  it('does not join two FTDs through the FMC that manages them', () => {
    const edges = [
      edge('m-1', 'fmc', 'ftd-1', 'management'),
      edge('m-2', 'fmc', 'ftd-2', 'management'),
      edge('u-1', 'users-1', 'ftd-1', 'vpn'),
    ];
    expect(connectEndpoints(['ftd-1', 'ftd-2'], edges).legs[0].path).toBeNull();
    // A VPN link to the FTD still counts.
    expect(connectEndpoints(['users-1', 'ftd-1'], edges).legs[0].path).toEqual(['users-1', 'ftd-1']);
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

describe('a remote user clicked in path mode', () => {
  const dana: TopologyNode = {
    id: 'meraki:4:cato:user:7',
    label: 'Dana Reyes',
    in_inventory: false,
    source: 'meraki',
    meraki: { org_ref: 4, node_id: 'cato:user:7', site_id: '__cato_pop__:New York', site_name: 'PoP New York', kind: 'user', status: 'online' },
  };
  const own: MerakiSubnet = {
    org_ref: 4,
    cidr: '10.88.0.11/32',
    name: 'Cato Client Dana Reyes',
    kind: 'user',
    site_id: '__cato_pop__:New York',
    site_name: 'PoP New York',
    node_id: 'cato:user:7',
    in_vpn: null,
  };
  const pool: MerakiSubnet = { ...own, org_ref: 1, cidr: '10.88.0.0/16', name: 'Behind Partner', kind: 'peer', site_id: '', site_name: '', node_id: 'p:Partner' };

  it('is picked with its own address, the same pick as typing it, so the leg is traced', () => {
    const pick = userPick(dana, [pool, own]);
    expect(pick).toEqual({
      key: 's:4:10.88.0.11:cato:user:7',
      node: 'meraki:4:cato:user:7',
      label: 'Dana Reyes (10.88.0.11) · PoP New York',
      subnet: own,
      address: '10.88.0.11',
    });
  });

  it('is a device pick when its address is not in the list, like any other node', () => {
    expect(userPick(dana, [pool])).toBeNull();
    expect(userPick(meraki('mx-a', 'a', 'appliance'), [pool, own])).toBeNull();
  });
});

describe('the traffic of a path', () => {
  it('reads the traffic to ask about', () => {
    expect(parseTraffic('')).toEqual({ protocol: '' });
    expect(parseTraffic(' Any ')).toEqual({ protocol: '' });
    expect(parseTraffic('tcp/443')).toEqual({ protocol: 'tcp', port: 443 });
    expect(parseTraffic('udp 53')).toEqual({ protocol: 'udp', port: 53 });
    expect(parseTraffic('8443')).toEqual({ protocol: 'tcp', port: 8443 });
    expect(parseTraffic('icmp')).toEqual({ protocol: 'icmp' });
    expect(parseTraffic('tcp/70000')).toBeNull();
    expect(parseTraffic('icmp/8')).toBeNull();
    expect(parseTraffic('https')).toBeNull();
  });
});

describe('path mode with inventory subnets', () => {
  const svi: MerakiSubnet = {
    org_ref: -4, provider: 'inventory', cidr: '10.50.0.0/24', name: 'VLAN 50 Users',
    kind: 'svi', site_id: '3', site_name: 'Campus', node_id: '12', in_vpn: null,
  };

  it('labels a subnet with its inventory group', () => {
    expect(subnetOptionLabel(svi)).toBe('10.50.0.0/24 - Campus - VLAN 50 Users');
  });

  it('labels a host with no group as inventory, not a VPN peer', () => {
    expect(subnetOptionLabel({ ...svi, site_id: '', site_name: '' })).toBe('10.50.0.0/24 - Inventory - VLAN 50 Users');
    expect(subnetOptionLabel({ ...svi, provider: 'meraki', site_name: '' })).toBe('10.50.0.0/24 - VPN peer - VLAN 50 Users');
  });

  it('names only the inputs that are shown', () => {
    expect(pathModeHint(true, true)).toBe('Click two or more devices on the map, or add sites, subnets and internet applications, to see how they reach one another.');
    expect(pathModeHint(false, true)).toBe('Click two or more devices on the map, or add subnets, IP addresses or internet applications, to see how they reach one another.');
    expect(pathModeHint(true, false)).toBe('Click two or more devices on the map, or add sites, to see how they reach one another.');
    expect(pathModeHint(false, false)).toBe('Click two or more devices on the map to see how they reach one another.');
  });
});

describe('an internet application as the destination', () => {
  const lan: MerakiSubnet = {
    org_ref: 1, provider: 'meraki', cidr: '192.0.2.0/24', name: 'VLAN 10 Data',
    kind: 'vlan', site_id: 's1', site_name: 'Branch 01', node_id: 'mx-a', in_vpn: true,
  };
  const files: MerakiSubnet = {
    org_ref: 2, provider: 'aws', cidr: '198.51.100.20/32', name: 'files-01',
    kind: 'host', site_id: 'vpc-1', site_name: 'Shared VPC', node_id: 'vpc-1', in_vpn: null,
    dns_names: ['storage.corp.example.com'],
  };
  const all = [lan, files];

  it('takes text the map does not know as an application or domain', () => {
    expect(appCandidate('youtube', all)).toBe('youtube');
    expect(appCandidate(' YouTube ', all)).toBe('YouTube');
    expect(appCandidate('youtube.com', all)).toBe('youtube.com');
    expect(appCandidate('Microsoft Teams', all)).toBe('Microsoft Teams');
    // A pasted URL stands for its host.
    expect(appCandidate('https://www.example.com/watch?v=1', all)).toBe('www.example.com');
    // A host whose name only holds the text is offered first, but does not stop it.
    expect(appCandidate('storage', all)).toBe('storage');
  });

  it('leaves addresses, subnets and known hosts to the map', () => {
    for (const typed of ['', 'y', '192.0.2.10', '192.0.2.0/24', '192.0', '203.0.113.5', '2001:db8::1', '::1']) {
      expect(appCandidate(typed, all), typed).toBeNull();
    }
    // A picker entry, or text the subnet list has entries for.
    expect(appCandidate(subnetOptionLabel(lan), all)).toBeNull();
    expect(appCandidate('branch 01', all)).toBeNull();
    // The DNS name of a collected host, typed or in a URL.
    expect(appCandidate('storage.corp.example.com', all)).toBeNull();
    expect(appCandidate('https://storage.corp.example.com/share', all)).toBeNull();
    expect(appCandidate('x'.repeat(129), all)).toBeNull();
  });

  it('offers the server matches, then always the typed text', () => {
    expect(appOptions(null, [{ name: 'YouTube', kind: 'application', source: 'catalog' }])).toEqual([]);
    expect(appOptions('youtube', [])).toEqual([
      { name: 'youtube', title: 'Internet application or domain: youtube', detail: 'Traced to the internet as the destination of its legs' },
    ]);
    const offered = appOptions('youtube', [
      { name: 'YouTube', kind: 'application', source: 'catalog' },
      { name: 'youtube', kind: 'application', source: 'other' },
      { name: 'Streaming Media', kind: 'category', source: 'catalog' },
      { name: 'youtube.com', kind: 'domain', source: '' },
    ]);
    expect(offered.map((o) => [o.name, o.detail])).toEqual([
      ['YouTube', 'Internet application · catalog'],
      ['youtube.com', 'Domain'],
      ['youtube', 'Traced to the internet as the destination of its legs'],
    ]);
  });

  it('is a pick with no map device, whose legs have no drawn path', () => {
    const app = appPick(' YouTube ');
    expect(app).toEqual({ key: 'a:youtube', label: 'Internet application: YouTube', app: 'YouTube' });
    expect(pickEnd(app)).toBe('YouTube');
    const source: PathPick = { key: 's:192.0.2.0/24:mx-a', node: 'mx-a', label: '192.0.2.0/24 · Branch 01', subnet: lan };
    const device: PathPick = { key: 'n:hub', node: 'hub', label: 'hub' };
    const result = connectPicks([source, app, device], EDGES);
    expect(result.legs.map((l) => [l.from.key, l.to.key, l.internet, l.path, l.sameDevice])).toEqual([
      ['s:192.0.2.0/24:mx-a', 'a:youtube', true, null, false],
      ['s:192.0.2.0/24:mx-a', 'n:hub', false, ['mx-a', 'hub'], false],
      ['a:youtube', 'n:hub', true, null, false],
    ]);
    expect([...result.nodeIds].sort()).toEqual(['hub', 'mx-a']);
  });
});
