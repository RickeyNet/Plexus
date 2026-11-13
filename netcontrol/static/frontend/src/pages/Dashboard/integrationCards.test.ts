import { describe, expect, it } from 'vitest';

import type { TopologySourceTypeCounts } from '@/api/dashboard';
import type { TopologySource } from '@/api/meraki';

import {
  availabilityRefOf,
  buildIntegrationCards,
  describeCounts,
  sourceEntityCounts,
  topologyMapLink,
} from './integrationCards';
import { SOURCES_LINK, parseAvailabilitySource, topologyAvailabilityLink } from './sourceHealth';

const NOW = Date.parse('2026-03-10T12:00:00Z');
const RECENT = new Date(NOW - 30 * 60 * 1000).toISOString();

function source(over: Partial<TopologySource> = {}): TopologySource {
  return {
    key: 'org:1',
    type: 'meraki',
    id: 1,
    name: 'Example Org',
    status: 'success',
    last_collected_at: RECENT,
    message: '',
    detail: '',
    warning_count: 0,
    collecting: false,
    can_collect: true,
    enabled: true,
    demo: false,
    ...over,
  };
}

function row(
  provider: string,
  org_ref: number,
  entity_type: string,
  counts: Partial<Pick<TopologySourceTypeCounts, 'up' | 'degraded' | 'down' | 'unknown' | 'muted'>> = {},
): TopologySourceTypeCounts {
  return { provider, org_ref, entity_type, up: 0, degraded: 0, down: 0, unknown: 0, ...counts };
}

describe('availabilityRefOf', () => {
  it('maps an organization source to its provider and id', () => {
    for (const type of ['meraki', 'cato', 'fmc', 'panorama', 'appgate'] as const) {
      expect(availabilityRefOf(source({ type, id: 7, key: 'org:7' }))).toEqual({ provider: type, orgRef: 7 });
    }
  });

  it('maps a cloud account to every row of its cloud', () => {
    for (const type of ['aws', 'azure', 'gcp'] as const) {
      expect(availabilityRefOf(source({ type, id: 3, key: `${type}:3` }))).toEqual({ provider: type, orgRef: null });
    }
  });

  it('has no rows for a source without an id', () => {
    expect(availabilityRefOf(source({ type: 'neighbors', id: null, key: 'neighbors' }))).toBeNull();
  });
});

describe('sourceEntityCounts', () => {
  const rows = [
    row('cato', 11, 'tunnel', { up: 4, down: 1 }),
    row('cato', 11, 'site', { up: 2, degraded: 1, down: 1 }),
    row('cato', 12, 'site', { up: 9 }),
    row('aws', -1, 'vpn_connection', { up: 1, unknown: 1 }),
    row('aws', -1, 'peering', { up: 2 }),
    row('cato', 11, 'mystery', { up: 1 }),
  ];

  it('keeps one organization, in display order, unknown types last', () => {
    const counts = sourceEntityCounts({ provider: 'cato', orgRef: 11 }, rows);
    expect(counts.map((c) => c.type)).toEqual(['site', 'tunnel', 'mystery']);
    expect(counts[0]).toEqual({ type: 'site', label: 'Sites', up: 2, degraded: 1, down: 1, unknown: 0, muted: 0, total: 4 });
    expect(counts[2].label).toBe('mystery');
  });

  it('takes every org_ref of a cloud', () => {
    const counts = sourceEntityCounts({ provider: 'aws', orgRef: null }, rows);
    expect(counts.map((c) => [c.label, c.total])).toEqual([
      ['VPN connections', 2],
      ['Peerings', 2],
    ]);
  });

  it('is empty for a source with no rows', () => {
    expect(sourceEntityCounts({ provider: 'fmc', orgRef: 5 }, rows)).toEqual([]);
  });

  it('counts muted entities in the total, apart from the problems', () => {
    const muted = [row('meraki', 1, 'device', { up: 3, muted: 2 }), row('meraki', 1, 'uplink', { muted: 1 })];
    const counts = sourceEntityCounts({ provider: 'meraki', orgRef: 1 }, muted);
    expect(counts.map((c) => [c.type, c.down, c.muted, c.total])).toEqual([
      ['device', 0, 2, 5],
      ['uplink', 0, 1, 1],
    ]);
  });
});

describe('buildIntegrationCards', () => {
  const rows = [
    row('cato', 11, 'site', { up: 3, down: 2 }),
    row('meraki', 1, 'device', { up: 10, degraded: 1 }),
    row('azure', -2, 'vpn_connection', { up: 2 }),
  ];
  const sources = [
    source({ key: 'neighbors', type: 'neighbors', id: null, name: 'Neighbors' }),
    source({ key: 'inventory', type: 'inventory', id: null, name: 'Inventory' }),
    source({ key: 'org:1', type: 'meraki', id: 1, name: 'Example Org' }),
    source({ key: 'org:11', type: 'cato', id: 11, name: 'Example Cato' }),
    source({ key: 'org:13', type: 'fmc', id: 13, name: 'Lab FMC', status: 'never', last_collected_at: null }),
    source({ key: 'azure:1', type: 'azure', id: 1, name: 'Sub A' }),
    source({ key: 'azure:2', type: 'azure', id: 2, name: 'Sub B' }),
    source({ key: 'aws:9', type: 'aws', id: 9, name: 'Off', enabled: false }),
    source({ key: 'org:99', type: 'panorama', id: 99, name: 'Demo', demo: true }),
  ];

  it('has one card per connected source, worst first', () => {
    const cards = buildIntegrationCards(sources, rows, NOW);
    expect(cards.map((c) => c.key)).toEqual(['org:11', 'org:1', 'azure:1', 'azure:2', 'org:13']);
  });

  it('carries health, counts and links', () => {
    const cards = buildIntegrationCards(sources, rows, NOW);
    const cato = cards.find((c) => c.key === 'org:11')!;
    expect(cato.health).toBe('healthy');
    expect(cato.typeLabel).toBe('Cato');
    expect(cato.down).toBe(2);
    expect(cato.counts?.map((c) => c.type)).toEqual(['site']);
    expect(cato.mapLink).toBe('/topology?provider=cato');
    expect(cato.availabilityLink).toBe(topologyAvailabilityLink({ provider: 'cato', orgRef: 11 }));
    expect(cato.combinedAccounts).toBe(1);

    const fmc = cards.find((c) => c.key === 'org:13')!;
    expect(fmc.health).toBe('never');
    expect(fmc.counts).toEqual([]);
    expect(fmc.sourcesLink).toBe(SOURCES_LINK);
  });

  it('says when cloud accounts share their counts', () => {
    const cards = buildIntegrationCards(sources, rows, NOW);
    const azure = cards.filter((c) => c.source.type === 'azure');
    expect(azure.map((c) => c.combinedAccounts)).toEqual([2, 2]);
    expect(azure[0].counts).toEqual(azure[1].counts);
    expect(azure[0].availabilityLink).toBe(topologyAvailabilityLink({ provider: 'azure', orgRef: null }));
  });

  it('has health only without availability data', () => {
    const cards = buildIntegrationCards(sources, undefined, NOW);
    expect(cards.every((c) => c.counts === null && c.availabilityLink === null)).toBe(true);
    // Without counts nothing is down: a failed collection still leads.
    const failed = buildIntegrationCards(
      [source({ key: 'org:1' }), source({ key: 'org:2', id: 2, name: 'Broken', status: 'failed' })],
      undefined,
      NOW,
    );
    expect(failed.map((c) => c.key)).toEqual(['org:2', 'org:1']);
  });

  it('does not rank a source with only muted problems as down', () => {
    const cards = buildIntegrationCards(
      [source({ key: 'org:1', name: 'A' }), source({ key: 'org:2', id: 2, name: 'B' })],
      [row('meraki', 1, 'device', { up: 1, muted: 4 }), row('meraki', 2, 'device', { up: 1, degraded: 1 })],
      NOW,
    );
    expect(cards.map((c) => [c.key, c.down, c.degraded])).toEqual([
      ['org:2', 0, 1],
      ['org:1', 0, 0],
    ]);
  });

  it('is empty with no connected source', () => {
    expect(buildIntegrationCards(sources.slice(0, 2), rows, NOW)).toEqual([]);
  });
});

describe('links', () => {
  it('round-trips the availability source parameter', () => {
    const link = topologyAvailabilityLink({ provider: 'cato', orgRef: 11 });
    expect(link).toBe('/monitoring/availability?source=cato%3A11#topology-availability');
    expect(parseAvailabilitySource('cato:11')).toEqual({ provider: 'cato', orgRef: 11 });
    expect(parseAvailabilitySource('aws')).toEqual({ provider: 'aws', orgRef: null });
    expect(parseAvailabilitySource('x:-1')).toEqual({ provider: 'x', orgRef: -1 });
    expect(parseAvailabilitySource('')).toBeNull();
    expect(parseAvailabilitySource(null)).toBeNull();
    expect(parseAvailabilitySource('cato:abc')).toBeNull();
  });

  it('links the map filtered to a provider', () => {
    expect(topologyMapLink('gcp')).toBe('/topology?provider=gcp');
  });

  it('describes counts in words', () => {
    expect(describeCounts({ up: 3, degraded: 0, down: 2, unknown: 1 })).toBe('3 up, 2 down, 1 unknown');
    expect(describeCounts({ up: 0, degraded: 0, down: 0, unknown: 0 })).toBe('none');
    expect(describeCounts({ up: 1, degraded: 0, down: 0, unknown: 0, muted: 2 })).toBe('1 up, 2 muted');
  });
});
