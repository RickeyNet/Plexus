import { describe, expect, it } from 'vitest';

import type { InventoryGroupFull, InventoryHost } from '@/api/inventory';

import {
  filterGroups,
  hostMatchesQuery,
  sortGroups,
  sortHostsForQuery,
} from './helpers';

const host = (
  id: number,
  partial: Partial<InventoryHost> = {},
): InventoryHost => ({
  id,
  hostname: `h${id}`,
  ip_address: `10.0.0.${id}`,
  device_type: 'cisco_ios',
  ...partial,
});

const group = (
  id: number,
  name: string,
  hosts: InventoryHost[] = [],
  partial: Partial<InventoryGroupFull> = {},
): InventoryGroupFull => ({
  id,
  name,
  hosts,
  ...partial,
});

describe('hostMatchesQuery', () => {
  it('matches against hostname/ip/device_type case-insensitively', () => {
    const h = host(1, { hostname: 'core-sw1', ip_address: '10.0.0.5', device_type: 'cisco_nxos' });
    expect(hostMatchesQuery(h, 'CORE')).toBe(true);
    expect(hostMatchesQuery(h, '10.0.0.5')).toBe(true);
    expect(hostMatchesQuery(h, 'nxos')).toBe(true);
    expect(hostMatchesQuery(h, 'mismatch')).toBe(false);
  });

  it('returns false on empty query', () => {
    expect(hostMatchesQuery(host(1), '')).toBe(false);
  });
});

describe('filterGroups', () => {
  const groups = [
    group(1, 'Core', [host(1, { hostname: 'core-sw1' })], { description: 'Core switches' }),
    group(2, 'Edge', [host(2, { hostname: 'edge-rtr', device_type: 'cisco_ios' })]),
  ];

  it('returns all groups when query is blank', () => {
    expect(filterGroups(groups, '')).toHaveLength(2);
  });

  it('matches by group name', () => {
    expect(filterGroups(groups, 'core')).toHaveLength(1);
  });

  it('matches by group description', () => {
    expect(filterGroups(groups, 'switches')).toHaveLength(1);
  });

  it('matches by host hostname inside group', () => {
    expect(filterGroups(groups, 'edge-rtr')).toHaveLength(1);
  });
});

describe('sortGroups', () => {
  const groups = [
    group(1, 'Bravo', [host(1), host(2)]),
    group(2, 'Alpha', [host(3)]),
    group(3, 'Charlie', []),
  ];

  it('preserves order for "custom"', () => {
    expect(sortGroups(groups, 'custom').map((g) => g.id)).toEqual([1, 2, 3]);
  });

  it('sorts by name ascending and descending', () => {
    expect(sortGroups(groups, 'name_asc').map((g) => g.name)).toEqual([
      'Alpha',
      'Bravo',
      'Charlie',
    ]);
    expect(sortGroups(groups, 'name_desc').map((g) => g.name)).toEqual([
      'Charlie',
      'Bravo',
      'Alpha',
    ]);
  });

  it('sorts by host count', () => {
    expect(sortGroups(groups, 'hosts_desc').map((g) => g.id)).toEqual([1, 2, 3]);
    expect(sortGroups(groups, 'hosts_asc').map((g) => g.id)).toEqual([3, 2, 1]);
  });
});

describe('sortHostsForQuery', () => {
  it('bubbles matching hosts to the top, leaves order alone otherwise', () => {
    const hosts = [host(1, { hostname: 'no-match' }), host(2, { hostname: 'core-x' })];
    expect(sortHostsForQuery(hosts, 'core').map((h) => h.id)).toEqual([2, 1]);
    expect(sortHostsForQuery(hosts, '').map((h) => h.id)).toEqual([1, 2]);
  });
});
