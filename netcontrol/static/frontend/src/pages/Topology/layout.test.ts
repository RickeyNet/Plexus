import { describe, expect, it } from 'vitest';

import type { TopologyEdge, TopologyNode } from '@/api/topology';

import { crowdedGroups, tidyLabel, tidyTreeLayout, TIDY_LABEL_MAX } from './layout';

const meraki = (id: string, kind: string, site: string): TopologyNode => ({
  id,
  label: id,
  in_inventory: false,
  source: 'meraki',
  meraki: { org_ref: 1, node_id: id, site_id: site, site_name: site, kind, status: 'online' },
});

const host = (id: number, label: string): TopologyNode => ({ id, label, in_inventory: true });

let edgeSeq = 0;
const link = (from: number | string, to: number | string, protocol = 'lldp'): TopologyEdge => ({
  id: `e${++edgeSeq}`,
  from,
  to,
  protocol,
});

/** Every node gets a spot, and no two nodes in a column are closer than a row. */
function expectNoOverlap(nodes: TopologyNode[], edges: TopologyEdge[]) {
  const pos = tidyTreeLayout(nodes, edges);
  expect(pos.size).toBe(nodes.length);
  const columns = new Map<number, number[]>();
  for (const p of pos.values()) columns.set(p.x, [...(columns.get(p.x) ?? []), p.y]);
  for (const ys of columns.values()) {
    ys.sort((a, b) => a - b);
    for (let i = 1; i < ys.length; i++) expect(ys[i] - ys[i - 1]).toBeGreaterThanOrEqual(48);
  }
  return pos;
}

describe('tidyTreeLayout', () => {
  it('grows a site to the right of its appliance', () => {
    const nodes = [
      meraki('ap1', 'wireless', 'a'),
      meraki('sw1', 'switch', 'a'),
      meraki('mx', 'appliance', 'a'),
      meraki('wan1', 'wan', 'a'),
      meraki('ap2', 'wireless', 'a'),
    ];
    const edges = [link('mx', 'sw1'), link('sw1', 'ap1'), link('sw1', 'ap2'), link('mx', 'wan1', 'wan')];
    const pos = expectNoOverlap(nodes, edges);
    expect(pos.get('mx')!.x).toBe(0);
    expect(pos.get('sw1')!.x).toBe(pos.get('wan1')!.x);
    expect(pos.get('ap1')!.x).toBeGreaterThan(pos.get('sw1')!.x);
    // A parent sits level with the middle of its children.
    expect(pos.get('sw1')!.y).toBe((pos.get('ap1')!.y + pos.get('ap2')!.y) / 2);
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
    const sep = pos.get('hub-sw')!.x;
    expect(pos.get('hub')!.x).toBe(0);
    expect(pos.get('spoke1')!.x).toBe(sep);
    expect(pos.get('spoke2')!.x).toBe(sep);
    expect(pos.get('spoke1-sw')!.x).toBe(sep * 2);
    // The hub's own site comes first, and other sites are set apart from it.
    expect(pos.get('hub-sw')!.y).toBeLessThan(pos.get('spoke1')!.y);
    expect(pos.get('spoke2')!.y - pos.get('spoke1')!.y).toBeGreaterThan(84);
  });

  it('stacks separate networks and unlinked devices without overlap', () => {
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
    const treeBottom = Math.max(...[1, 2, 3, 4, 5].map((id) => pos.get(id)!.y));
    for (const id of [6, 7, 8]) expect(pos.get(id)!.y).toBeGreaterThan(treeBottom);
  });

  it('is deterministic and survives cycles and a large fan-out', () => {
    const nodes = [meraki('mx', 'appliance', 'a')];
    const edges: TopologyEdge[] = [];
    for (let i = 0; i < 300; i++) {
      nodes.push(meraki(`sw${i}`, 'switch', 'a'));
      edges.push(link('mx', `sw${i}`));
      if (i) edges.push(link(`sw${i - 1}`, `sw${i}`));
    }
    const first = expectNoOverlap(nodes, edges);
    const second = tidyTreeLayout([...nodes].reverse(), [...edges].reverse());
    expect([...second.entries()].sort()).toEqual([...first.entries()].sort());
  });

  it('handles an empty map', () => {
    expect(tidyTreeLayout([], []).size).toBe(0);
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

  it('flows sites into columns instead of one tall strip', () => {
    const pos = expectNoOverlap(nodes, edges);
    const xs = [...pos.values()].map((p) => p.x);
    const ys = [...pos.values()].map((p) => p.y);
    const width = Math.max(...xs) - Math.min(...xs);
    const height = Math.max(...ys) - Math.min(...ys);
    expect(width / height).toBeGreaterThan(0.8);
    expect(width / height).toBeLessThan(3.5);
    // Each site is a tree of its own again: appliance, then switch, then APs.
    expect(pos.get('site07-sw')!.x).toBeGreaterThan(pos.get('site07-mx')!.x);
    expect(pos.get('site07-ap1')!.x).toBeGreaterThan(pos.get('site07-sw')!.x);
    // Sites read in name order down the first column.
    expect(pos.get('hub')!.x).toBe(pos.get('site00-mx')!.x);
    expect(pos.get('site00-mx')!.y).toBeGreaterThan(pos.get('hub')!.y);
  });

  it('keeps every site clear of the others, so all frames can be drawn', () => {
    const pos = tidyTreeLayout(nodes, edges);
    const placed = nodes.map((n) => ({ group: n.meraki!.site_id, ...pos.get(n.id)! }));
    expect(crowdedGroups(placed, 60, 34).size).toBe(0);
  });
});
