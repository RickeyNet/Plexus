import { describe, expect, it } from 'vitest';

import type { TopologyData, TopologyEdge, TopologyNode } from '@/api/topology';

import { filterBySource, mapProviders, nodeProvider } from './helpers';

function node(id: string, provider?: string, inventory = false): TopologyNode {
  return {
    id,
    label: id,
    in_inventory: inventory,
    source: provider && !inventory ? 'meraki' : undefined,
    meraki: provider
      ? { org_ref: 1, node_id: id, site_id: 's', site_name: 'S', kind: 'appliance', status: 'online', provider }
      : null,
  };
}

function edge(id: string, from: string, to: string, provider?: string): TopologyEdge {
  return { id, from, to, source: provider ? 'meraki' : undefined, provider };
}

const DATA: TopologyData = {
  nodes: [
    node('sw1'), // inventory only
    node('mx1', 'meraki'),
    node('vpc1', 'aws'),
    node('vpc2', 'aws'),
    node('cato1', 'cato'),
    node('core', 'meraki', true), // inventory host matched to a Meraki device
    { ...node('old'), meraki: { org_ref: 2, node_id: 'old', site_id: 's', site_name: 'S', kind: 'switch', status: 'online' } },
  ],
  edges: [
    edge('e1', 'vpc1', 'vpc2', 'aws'),
    edge('e2', 'vpc1', 'cato1', 'aws'), // cross-integration join
    edge('e3', 'mx1', 'core', 'meraki'),
    edge('e4', 'sw1', 'core'), // inventory CDP link
  ],
} as TopologyData;

describe('source filter', () => {
  it('names the provider of a node, defaulting old snapshots to Meraki', () => {
    expect(nodeProvider(DATA.nodes[0])).toBe('');
    expect(nodeProvider(DATA.nodes[2])).toBe('aws');
    expect(nodeProvider(DATA.nodes[6])).toBe('meraki');
  });

  it('lists the providers on the map in a stable order', () => {
    expect(mapProviders(DATA)).toEqual(['meraki', 'cato', 'aws']);
    expect(mapProviders(undefined)).toEqual([]);
    // A Cisco FMC sits between Cato and the clouds.
    const withFmc = { ...DATA, nodes: [...DATA.nodes, node('ftd1', 'fmc')] } as TopologyData;
    expect(mapProviders(withFmc)).toEqual(['meraki', 'cato', 'fmc', 'aws']);
  });

  it('keeps only one provider and the links inside it', () => {
    const aws = filterBySource(DATA, 'provider:aws')!;
    expect(aws.nodes.map((n) => n.id)).toEqual(['vpc1', 'vpc2']);
    expect(aws.edges.map((e) => e.id)).toEqual(['e1']);
    const meraki = filterBySource(DATA, 'provider:meraki')!;
    expect(meraki.nodes.map((n) => n.id)).toEqual(['mx1', 'core', 'old']);
    expect(meraki.edges.map((e) => e.id)).toEqual(['e3']);
  });

  it('keeps the existing choices working', () => {
    expect(filterBySource(DATA, 'all')).toBe(DATA);
    expect(filterBySource(DATA, 'inventory')!.nodes.map((n) => n.id)).toEqual(['sw1', 'core', 'old']);
    expect(filterBySource(DATA, 'inventory')!.edges.map((e) => e.id)).toEqual(['e4']);
    const all = filterBySource(DATA, 'meraki')!;
    expect(all.nodes.map((n) => n.id)).toEqual(['mx1', 'vpc1', 'vpc2', 'cato1', 'core', 'old']);
    expect(all.edges.map((e) => e.id)).toEqual(['e1', 'e2', 'e3']);
  });
});

describe('source filter with devices of two integrations', () => {
  const kind = (n: TopologyNode, k: string): TopologyNode => ({ ...n, meraki: { ...n.meraki!, kind: k } });
  const tunnel = (id: string, from: string, to: string, provider: string): TopologyEdge => ({
    ...edge(id, from, to, provider),
    protocol: 'vpn',
  });
  const SHARED: TopologyData = {
    nodes: [
      node('vpc', 'aws'),
      { ...node('vsocket', 'cato'), also_providers: ['aws'] }, // a Cato vSocket on an AWS instance
      kind(node('pop', 'cato'), 'cloud'),
      kind(node('backbone', 'cato'), 'cloud'),
      { ...node('vmx', 'meraki'), also_providers: ['aws'] },
      node('spoke', 'meraki'),
    ],
    edges: [
      { ...edge('attach', 'vsocket', 'vpc', 'aws'), protocol: 'cloud' },
      tunnel('to-pop', 'vsocket', 'pop', 'cato'),
      tunnel('pop-backbone', 'pop', 'backbone', 'cato'),
      { ...edge('vmx-attach', 'vmx', 'vpc', 'aws'), protocol: 'cloud' },
      tunnel('autovpn', 'vmx', 'spoke', 'meraki'),
    ],
  } as TopologyData;

  it('shows the device in both, with its tunnel to the PoP it connects to', () => {
    const aws = filterBySource(SHARED, 'provider:aws')!;
    expect(aws.nodes.map((n) => n.id)).toEqual(['vpc', 'vsocket', 'pop', 'vmx']);
    expect(aws.edges.map((e) => e.id)).toEqual(['attach', 'to-pop', 'vmx-attach']);
    const cato = filterBySource(SHARED, 'provider:cato')!;
    expect(cato.nodes.map((n) => n.id)).toEqual(['vsocket', 'pop', 'backbone']);
    expect(cato.edges.map((e) => e.id)).toEqual(['to-pop', 'pop-backbone']);
  });
});
