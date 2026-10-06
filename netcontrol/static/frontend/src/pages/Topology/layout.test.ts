import { describe, expect, it } from 'vitest';

import type { TopologyEdge, TopologyNode } from '@/api/topology';

import { crowdedGroups, orderSources, SOURCE_GAP, tidyLabel, tidyTree, tidyTreeLayout, TIDY_LABEL_MAX } from './layout';

const meraki = (id: string, kind: string, site: string, provider?: string): TopologyNode => ({
  id,
  label: id,
  in_inventory: false,
  source: 'meraki',
  meraki: { org_ref: 1, node_id: id, site_id: site, site_name: site, kind, status: 'online', provider },
});

const cato = (id: string, kind: string, site: string) => meraki(id, kind, site, 'cato');

const host = (id: number, label: string): TopologyNode => ({ id, label, in_inventory: true });

let edgeSeq = 0;
const link = (from: number | string, to: number | string, protocol = 'lldp'): TopologyEdge => ({
  id: `e${++edgeSeq}`,
  from,
  to,
  protocol,
});

/** Every node gets a spot, and no two nodes in a row are closer than a label's width. */
function expectNoOverlap(nodes: TopologyNode[], edges: TopologyEdge[]) {
  const pos = tidyTreeLayout(nodes, edges);
  expect(pos.size).toBe(nodes.length);
  const rows = new Map<number, number[]>();
  for (const p of pos.values()) rows.set(p.y, [...(rows.get(p.y) ?? []), p.x]);
  for (const xs of rows.values()) {
    xs.sort((a, b) => a - b);
    for (let i = 1; i < xs.length; i++) expect(xs[i] - xs[i - 1]).toBeGreaterThanOrEqual(120);
  }
  return pos;
}

describe('tidyTreeLayout', () => {
  it('grows a site down from its appliance', () => {
    const nodes = [
      meraki('ap1', 'wireless', 'a'),
      meraki('sw1', 'switch', 'a'),
      meraki('mx', 'appliance', 'a'),
      meraki('wan1', 'wan', 'a'),
      meraki('ap2', 'wireless', 'a'),
    ];
    const edges = [link('mx', 'sw1'), link('sw1', 'ap1'), link('sw1', 'ap2'), link('mx', 'wan1', 'wan')];
    const pos = expectNoOverlap(nodes, edges);
    // The WAN uplink sits just above its appliance, at the top of the map.
    expect(pos.get('wan1')).toEqual({ x: pos.get('mx')!.x, y: 0 });
    expect(pos.get('mx')!.y).toBeGreaterThan(0);
    expect(pos.get('sw1')!.y).toBeGreaterThan(pos.get('mx')!.y);
    expect(pos.get('ap1')!.y).toBeGreaterThan(pos.get('sw1')!.y);
    expect(pos.get('ap1')!.y).toBe(pos.get('ap2')!.y);
    // A parent sits over the middle of its children.
    expect(pos.get('sw1')!.x).toBe((pos.get('ap1')!.x + pos.get('ap2')!.x) / 2);
  });

  it('follows cables before VPN tunnels', () => {
    const nodes = [
      meraki('hub', 'appliance', 'hq'),
      meraki('hub-sw', 'switch', 'hq'),
      meraki('spoke1', 'appliance', 's1'),
      meraki('spoke1-sw', 'switch', 's1'),
      meraki('spoke2', 'appliance', 's2'),
    ];
    const edges = [
      link('hub', 'spoke1', 'vpn'),
      link('hub', 'spoke2', 'vpn'),
      link('spoke1', 'spoke2', 'vpn'),
      link('hub', 'hub-sw'),
      link('spoke1', 'spoke1-sw'),
      // The switches also see each other over a routed adjacency.
      link('hub-sw', 'spoke1-sw', 'ospf'),
    ];
    const pos = expectNoOverlap(nodes, edges);
    const level = pos.get('hub-sw')!.y - pos.get('hub')!.y;
    expect(pos.get('hub')!.y).toBe(0);
    expect(pos.get('spoke1')!.y).toBe(level);
    expect(pos.get('spoke2')!.y).toBe(level);
    expect(pos.get('spoke1-sw')!.y).toBe(level * 2);
    // The hub's own site comes first, and other sites are set apart from it.
    expect(pos.get('hub-sw')!.x).toBeLessThan(pos.get('spoke1')!.x);
    expect(pos.get('spoke2')!.x - pos.get('spoke1')!.x).toBeGreaterThan(120);
  });

  it('lays separate networks side by side and unlinked devices under them', () => {
    const nodes = [
      host(1, 'core-1'),
      host(2, 'access-1'),
      host(3, 'access-2'),
      host(4, 'lab-1'),
      host(5, 'lab-2'),
      host(6, 'spare-1'),
      host(7, 'spare-2'),
      host(8, 'spare-3'),
    ];
    const edges = [link(1, 2), link(1, 3), link(2, 3), link(4, 5), link(9, 1), link(4, 4)];
    const pos = expectNoOverlap(nodes, edges);
    const top = (ids: number[]) => Math.min(...ids.map((id) => pos.get(id)!.y));
    expect(top([4, 5])).toBe(top([1, 2, 3]));
    expect(pos.get(4)!.x).toBeGreaterThan(Math.max(...[1, 2, 3].map((id) => pos.get(id)!.x)));
    const treeBottom = Math.max(...[1, 2, 3, 4, 5].map((id) => pos.get(id)!.y));
    for (const id of [6, 7, 8]) expect(pos.get(id)!.y).toBeGreaterThan(treeBottom);
  });

  it('is deterministic and wraps a large fan-out into a grid', () => {
    const nodes = [meraki('mx', 'appliance', 'a')];
    const edges: TopologyEdge[] = [];
    for (let i = 0; i < 300; i++) {
      nodes.push(meraki(`sw${i}`, 'switch', 'a'));
      edges.push(link('mx', `sw${i}`));
      if (i) edges.push(link(`sw${i - 1}`, `sw${i}`));
    }
    const first = expectNoOverlap(nodes, edges);
    const xs = [...first.values()].map((p) => p.x);
    const ys = [...first.values()].map((p) => p.y);
    expect(Math.max(...xs) - Math.min(...xs)).toBeLessThan(300 * 120 / 4);
    expect(Math.max(...ys) - Math.min(...ys)).toBeLessThan(Math.max(...xs) - Math.min(...xs));
    const second = tidyTreeLayout([...nodes].reverse(), [...edges].reverse());
    expect([...second.entries()].sort()).toEqual([...first.entries()].sort());
  });

  it('handles an empty map', () => {
    expect(tidyTreeLayout([], []).size).toBe(0);
  });
});

describe('tidyTree sources', () => {
  // The inventory core is cabled to a Meraki MX, which also has a tunnel to
  // a Cato PoP. Each source is still drawn on its own.
  const nodes: TopologyNode[] = [
    host(1, 'core'),
    host(2, 'access'),
    meraki('mx', 'appliance', 'branch'),
    meraki('ms', 'switch', 'branch'),
    cato('pop', 'cloud', 'cloud'),
    cato('sock', 'appliance', 'office'),
    meraki('vpc', 'vpc', 'prod', 'aws'),
  ];
  const edges: TopologyEdge[] = [
    link(1, 2),
    link(1, 'mx'),
    link('mx', 'ms'),
    link('mx', 'pop', 'vpn'),
    link('sock', 'pop', 'vpn'),
  ];

  it('draws each source as a region of its own, side by side', () => {
    const pos = expectNoOverlap(nodes, edges);
    const xs = (ids: (number | string)[]) => ids.map((id) => pos.get(id)!.x);
    const inventory = xs([1, 2]);
    const merakiXs = xs(['mx', 'ms']);
    const catoXs = xs(['pop', 'sock']);
    expect(Math.min(...merakiXs) - Math.max(...inventory)).toBeGreaterThanOrEqual(SOURCE_GAP);
    expect(Math.min(...catoXs) - Math.max(...merakiXs)).toBeGreaterThanOrEqual(SOURCE_GAP);
    expect(pos.get('vpc')!.x - Math.max(...catoXs)).toBeGreaterThanOrEqual(SOURCE_GAP);
    // Their tops are level, and a link to another source does not pull a
    // node out of its own: the MX heads the Meraki region instead of hanging
    // under the inventory core.
    const top = (ids: (number | string)[]) => Math.min(...ids.map((id) => pos.get(id)!.y));
    expect(top(['mx', 'ms'])).toBe(top([1, 2]));
    expect(top(['pop', 'sock'])).toBe(top([1, 2]));
    expect(pos.get('vpc')!.y).toBe(top([1, 2]));
  });

  it('orders the sources: the inventory, then the integrations', () => {
    expect(orderSources(['zz', 'cato', 'aws', '', 'meraki'])).toEqual(['', 'meraki', 'cato', 'aws', 'zz']);
  });
});

describe('tidyLabel', () => {
  it('shortens only long labels', () => {
    expect(tidyLabel('core-sw1')).toBe('core-sw1');
    expect(tidyLabel('x'.repeat(80))).toHaveLength(TIDY_LABEL_MAX);
  });
});

describe('crowdedGroups', () => {
  it('flags a group whose frame would enclose another group’s node', () => {
    const placed = [
      { group: 'hub', x: 0, y: 500 },
      { group: 'hub', x: 300, y: 0 },
      { group: 'spoke', x: 300, y: 300 },
      { group: 'spoke', x: 600, y: 300 },
      { group: '', x: 900, y: 900 },
    ];
    expect(crowdedGroups(placed, 60, 34)).toEqual(new Set(['hub']));
  });
});

describe('tidyTreeLayout on a large map', () => {
  const nodes: TopologyNode[] = [meraki('hub', 'appliance', 'hq'), meraki('hub-sw', 'switch', 'hq')];
  const edges: TopologyEdge[] = [link('hub', 'hub-sw')];
  for (let i = 0; i < 60; i++) {
    const site = `site${String(i).padStart(2, '0')}`;
    nodes.push(
      meraki(`${site}-mx`, 'appliance', site),
      meraki(`${site}-sw`, 'switch', site),
      meraki(`${site}-ap1`, 'wireless', site),
      meraki(`${site}-ap2`, 'wireless', site),
    );
    edges.push(
      link(`${site}-mx`, `${site}-sw`),
      link(`${site}-sw`, `${site}-ap1`),
      link(`${site}-sw`, `${site}-ap2`),
      link('hub', `${site}-mx`, 'vpn'),
    );
  }

  it('wraps the sites under the hub into rows instead of one wide strip', () => {
    const pos = expectNoOverlap(nodes, edges);
    const xs = [...pos.values()].map((p) => p.x);
    const ys = [...pos.values()].map((p) => p.y);
    const width = Math.max(...xs) - Math.min(...xs);
    const height = Math.max(...ys) - Math.min(...ys);
    expect(width / height).toBeGreaterThan(0.8);
    expect(width / height).toBeLessThan(3.5);
    // The hub is on top, every site a small tree under it: appliance, then
    // switch, then APs.
    expect(pos.get('hub')!.y).toBe(Math.min(...ys));
    expect(pos.get('site07-sw')!.y).toBeGreaterThan(pos.get('site07-mx')!.y);
    expect(pos.get('site07-ap1')!.y).toBeGreaterThan(pos.get('site07-sw')!.y);
    // Sites read in name order along each row, over several rows.
    expect(pos.get('site01-mx')!.y).toBe(pos.get('site00-mx')!.y);
    expect(pos.get('site01-mx')!.x).toBeGreaterThan(pos.get('site00-mx')!.x);
    expect(pos.get('site59-mx')!.y).toBeGreaterThan(pos.get('site00-mx')!.y);
  });

  it('keeps every site clear of the others, so all frames can be drawn', () => {
    const pos = tidyTreeLayout(nodes, edges);
    const placed = nodes.map((n) => ({ group: n.meraki!.site_id, ...pos.get(n.id)! }));
    expect(crowdedGroups(placed, 60, 34).size).toBe(0);
  });
});

describe('tidyTree site frames', () => {
  // A hub VPC with its own gateways, a transit gateway, VPCs peered with it
  // (one of them not collected) and customer gateways with no links.
  const nodes: TopologyNode[] = [
    meraki('hub', 'vpc', 'hub'),
    meraki('hub-igw', 'wan', 'hub'),
    meraki('hub-nat', 'cloud', 'hub'),
    meraki('hub-fw', 'appliance', 'hub'),
    meraki('tgw', 'cloud', 'transit'),
    meraki('cgw1', 'vpn_peer', 'transit'),
    meraki('cgw2', 'vpn_peer', 'transit'),
  ];
  const edges: TopologyEdge[] = [
    link('hub', 'hub-igw', 'wan'),
    link('hub', 'hub-nat', 'cloud'),
    link('hub', 'hub-fw', 'cloud'),
    link('hub', 'tgw', 'cloud'),
  ];
  for (const peer of ['dev', 'prod', 'stub']) {
    nodes.push(meraki(peer, 'vpc', peer));
    edges.push(link('hub', peer, 'cloud'));
    if (peer !== 'stub') {
      nodes.push(meraki(`${peer}-igw`, 'wan', peer));
      edges.push(link(peer, `${peer}-igw`, 'wan'));
    }
  }

  it('keeps a hub over its own devices, so no site frame is dropped', () => {
    const { positions, pieces } = tidyTree(nodes, edges);
    const ownXs = ['hub-nat', 'hub-fw'].map((id) => positions.get(id)!.x);
    expect(positions.get('hub')!.x).toBeGreaterThanOrEqual(Math.min(...ownXs));
    expect(positions.get('hub')!.x).toBeLessThanOrEqual(Math.max(...ownXs));
    const placed = nodes.map((n) => ({ group: pieces.get(n.id)!, ...positions.get(n.id)! }));
    expect(crowdedGroups(placed, 60, 34).size).toBe(0);
  });

  it('frames each place a site is drawn in on its own', () => {
    const { pieces } = tidyTree(nodes, edges);
    // The hub and its gateways are one piece, each peered VPC another.
    expect(pieces.get('hub-igw')).toBe(pieces.get('hub'));
    expect(pieces.get('hub-fw')).toBe(pieces.get('hub'));
    expect(pieces.get('dev-igw')).toBe(pieces.get('dev'));
    expect(pieces.get('dev')).not.toBe(pieces.get('prod'));
    // The transit gateway under the hub and the unlinked customer gateways
    // are two pieces of the transit site, not one frame across the map.
    expect(pieces.get('cgw1')).toBe(pieces.get('cgw2'));
    expect(pieces.get('tgw')).not.toBe(pieces.get('cgw1'));
    expect(pieces.get('tgw')!.startsWith('m:1:transit#')).toBe(true);
  });

  it('leaves nodes outside any site out of the pieces', () => {
    const { pieces } = tidyTree([host(1, 'core'), host(2, 'edge')], [link(1, 2)]);
    expect(pieces.size).toBe(0);
  });
});

describe('tidyTree WAN uplinks', () => {
  it('keeps the uplinks in a row over an appliance with a large site behind it', () => {
    const nodes = [
      meraki('mx', 'appliance', 'a'),
      meraki('wan1', 'wan', 'a'),
      meraki('wan2', 'wan', 'a'),
      meraki('core', 'switch', 'a'),
    ];
    const edges = [link('mx', 'wan1', 'wan'), link('mx', 'wan2', 'wan'), link('mx', 'core')];
    for (let s = 0; s < 4; s++) {
      nodes.push(meraki(`sw${s}`, 'switch', 'a'));
      edges.push(link('core', `sw${s}`));
      for (let a = 0; a < 12; a++) {
        nodes.push(meraki(`sw${s}-ap${a}`, 'wireless', 'a'));
        edges.push(link(`sw${s}`, `sw${s}-ap${a}`));
      }
    }
    const pos = expectNoOverlap(nodes, edges);
    const mx = pos.get('mx')!;
    expect(pos.get('wan1')).toEqual({ x: mx.x - 60, y: mx.y - 110 });
    expect(pos.get('wan2')).toEqual({ x: mx.x + 60, y: mx.y - 110 });
    expect(tidyTree(nodes, edges).pieces.get('wan1')).toBe(tidyTree(nodes, edges).pieces.get('mx'));
  });

  it('leaves an uplink that leads somewhere in the tree', () => {
    const nodes = [meraki('mx', 'appliance', 'a'), meraki('wan1', 'wan', 'a'), meraki('isp', 'external', 'a')];
    const edges = [link('mx', 'wan1', 'wan'), link('wan1', 'isp')];
    const pos = expectNoOverlap(nodes, edges);
    expect(pos.get('wan1')!.y).toBeGreaterThan(pos.get('mx')!.y);
    expect(pos.get('isp')!.y).toBeGreaterThan(pos.get('wan1')!.y);
  });
});

describe('tidyTree Cato backbone', () => {
  // 20 PoPs on the backbone, each in a box with its 30 users.
  const popId = (p: number) => `pop${p}`;
  const userId = (p: number, u: number) => `u${p}-${u}`;
  const nodes: TopologyNode[] = [cato('cato:cloud', 'cloud', 'cloud')];
  const edges: TopologyEdge[] = [];
  for (let p = 0; p < 20; p++) {
    nodes.push(cato(popId(p), 'cloud', `pop-box${p}`));
    edges.push(link(popId(p), 'cato:cloud', 'vpn'));
    for (let u = 0; u < 30; u++) {
      nodes.push(cato(userId(p, u), 'user', `pop-box${p}`));
      edges.push(link(userId(p, u), popId(p), 'vpn'));
    }
  }

  it('puts every PoP in one row, far enough down for steep links', () => {
    const { positions } = tidyTree(nodes, edges);
    const cloud = positions.get('cato:cloud')!;
    const pops = Array.from({ length: 20 }, (_, p) => positions.get(popId(p))!);
    // One row: no link from the backbone runs past a row of PoPs and users.
    expect(new Set(pops.map((p) => p.y)).size).toBe(1);
    const halfWidth = Math.max(...pops.map((p) => Math.abs(p.x - cloud.x)));
    // A wide row drops further than one level, so the far links come down steeply.
    expect(pops[0].y - cloud.y).toBeGreaterThan(170);
    expect(pops[0].y - cloud.y).toBeGreaterThanOrEqual(4 * Math.sqrt(halfWidth));
  });

  it('frames each PoP with its users', () => {
    const { positions, pieces } = tidyTree(nodes, edges);
    for (let p = 0; p < 20; p++) {
      const pop = positions.get(popId(p))!;
      const users = Array.from({ length: 30 }, (_, u) => userId(p, u));
      expect(new Set([popId(p), ...users].map((id) => pieces.get(id))).size).toBe(1);
      const xs = users.map((id) => positions.get(id)!.x);
      expect(pop.x).toBeGreaterThanOrEqual(Math.min(...xs));
      expect(pop.x).toBeLessThanOrEqual(Math.max(...xs));
      expect(Math.min(...users.map((id) => positions.get(id)!.y))).toBeGreaterThan(pop.y);
    }
  });
});

describe('tidyTree remote users', () => {
  // A Cato account: a Socket and a PoP on the backbone, 200 users on the PoP.
  const nodes: TopologyNode[] = [
    cato('sock', 'appliance', 'branch'),
    cato('pop', 'cloud', 'cloud'),
    cato('cato:cloud', 'cloud', 'cloud'),
  ];
  const edges: TopologyEdge[] = [link('sock', 'pop', 'vpn'), link('pop', 'cato:cloud', 'vpn')];
  for (let i = 0; i < 200; i++) {
    const id = `user${String(i).padStart(3, '0')}`;
    nodes.push(cato(id, 'user', 'users-pop'));
    edges.push(link(id, 'pop', 'vpn'));
  }
  const users = nodes.filter((n) => n.meraki?.kind === 'user');

  it('draws the users as a grid under their PoP, not as one long row', () => {
    const { positions, pieces } = tidyTree(nodes, edges);
    const pop = positions.get('pop')!;
    const xs = users.map((u) => positions.get(u.id)!.x);
    const ys = new Set(users.map((u) => positions.get(u.id)!.y));
    expect(ys.size).toBeGreaterThan(3);
    expect(Math.min(...ys)).toBeGreaterThan(pop.y);
    expect(Math.max(...xs) - Math.min(...xs)).toBeLessThan(200 * 120 / 4);
    // The backbone is on top, and the PoP sits over its Socket and its users.
    expect(positions.get('cato:cloud')!.y).toBeLessThan(pop.y);
    expect(positions.get('sock')!.y).toBeGreaterThan(pop.y);
    expect(pop.x).toBeGreaterThanOrEqual(Math.min(positions.get('sock')!.x, ...xs));
    expect(pop.x).toBeLessThanOrEqual(Math.max(...xs));
    // No two users share a spot, and they are framed together.
    expect(new Set(users.map((u) => JSON.stringify(positions.get(u.id)))).size).toBe(users.length);
    expect(new Set(users.map((u) => pieces.get(u.id))).size).toBe(1);
  });

  it('keeps the users with their PoP on a large map', () => {
    const big = [...nodes];
    const bigEdges = [...edges];
    for (let i = 0; i < 80; i++) {
      big.push(cato(`s${i}`, 'appliance', `site${i}`), cato(`s${i}-sw`, 'switch', `site${i}`));
      bigEdges.push(link(`s${i}`, `s${i}-sw`), link(`s${i}`, 'pop', 'vpn'));
    }
    const { positions, pieces } = tidyTree(big, bigEdges);
    const pop = positions.get('pop')!;
    const placed = users.map((u) => positions.get(u.id)!);
    expect(placed.every((p) => p.y > pop.y && p.y < pop.y + 3000 && Math.abs(p.x - pop.x) < 4000)).toBe(true);
    expect(new Set(users.map((u) => pieces.get(u.id))).size).toBe(1);
  });
});
