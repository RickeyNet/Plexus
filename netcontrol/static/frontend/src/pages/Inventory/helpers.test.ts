import { describe, expect, it } from 'vitest';

import { groupLabel, type InventoryGroupFull, type InventoryHost } from '@/api/inventory';

import {
  applyGroupOrder,
  descendantIds,
  filterGroups,
  hiddenByCollapsedAncestor,
  hostMatchesQuery,
  isAwsInstanceId,
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

  it('matches against the AWS instance ID', () => {
    const h = host(1, { aws_instance_id: 'i-0123456789abcdef0' });
    expect(hostMatchesQuery(h, 'i-0123456789')).toBe(true);
    expect(hostMatchesQuery(host(2, { aws_instance_id: '' }), 'i-0')).toBe(false);
  });
});

describe('isAwsInstanceId', () => {
  it('accepts short and long instance IDs case-insensitively', () => {
    expect(isAwsInstanceId('i-0123abcd')).toBe(true);
    expect(isAwsInstanceId('i-0123456789abcdef0')).toBe(true);
    expect(isAwsInstanceId('I-0123456789ABCDEF0')).toBe(true);
    expect(isAwsInstanceId('i-0a99001')).toBe(true); // the demo account's
  });

  it('rejects anything else', () => {
    expect(isAwsInstanceId('')).toBe(false);
    expect(isAwsInstanceId('i-')).toBe(false);
    expect(isAwsInstanceId('i-0123456789abcdef01')).toBe(false); // 18 hex digits
    expect(isAwsInstanceId('i-0123456789abcdeg0')).toBe(false); // non-hex
    expect(isAwsInstanceId('vol-0123456789abcdef0')).toBe(false);
    expect(isAwsInstanceId(' i-0123456789abcdef0')).toBe(false); // untrimmed
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

describe('group hierarchy', () => {
  // Tree order as the API returns it: Meraki, its two sites, then Core.
  const tree = [
    group(1, 'Meraki', [], { parent_id: null, depth: 0, path: 'Meraki' }),
    group(2, 'Zulu', [host(1)], { parent_id: 1, depth: 1, path: 'Meraki / Zulu' }),
    group(3, 'Alpha', [host(2), host(3)], { parent_id: 1, depth: 1, path: 'Meraki / Alpha' }),
    group(4, 'Core', [host(4, { hostname: 'core-sw' })], { parent_id: null, depth: 0, path: 'Core' }),
    group(5, 'Deep', [], { parent_id: 3, depth: 2, path: 'Meraki / Alpha / Deep' }),
  ];

  it('sorts among siblings and keeps sub-groups under their parent', () => {
    expect(sortGroups(tree, 'name_asc').map((g) => g.id)).toEqual([4, 1, 3, 5, 2]);
    expect(sortGroups(tree, 'hosts_desc').map((g) => g.id)).toEqual([4, 1, 3, 5, 2]);
    expect(sortGroups(tree, 'custom').map((g) => g.id)).toEqual([1, 2, 3, 5, 4]);
  });

  it('applies a saved order among siblings', () => {
    expect(applyGroupOrder(tree, [4, 3, 1, 2]).map((g) => g.id)).toEqual([4, 1, 3, 5, 2]);
  });

  it('keeps the ancestors of a matching sub-group, and matches the path', () => {
    expect(filterGroups(tree, 'deep').map((g) => g.id)).toEqual([1, 3, 5]);
    expect(filterGroups(tree, 'meraki / zulu').map((g) => g.id)).toEqual([1, 2]);
    expect(filterGroups(tree, 'core-sw').map((g) => g.id)).toEqual([4]);
  });

  it('finds descendants and the groups a collapsed ancestor hides', () => {
    expect([...descendantIds(tree, 1)].sort()).toEqual([2, 3, 5]);
    expect([...descendantIds(tree, 5)]).toEqual([]);
    expect([...hiddenByCollapsedAncestor(tree, new Set([3]))]).toEqual([5]);
    expect([...hiddenByCollapsedAncestor(tree, new Set([1]))].sort()).toEqual([2, 3, 5]);
  });

  it('labels a group by its path, or its name without one', () => {
    expect(groupLabel(tree[4])).toBe('Meraki / Alpha / Deep');
    expect(groupLabel({ name: 'Flat' })).toBe('Flat');
  });
});

describe('sortHostsForQuery', () => {
  it('bubbles matching hosts to the top, leaves order alone otherwise', () => {
    const hosts = [host(1, { hostname: 'no-match' }), host(2, { hostname: 'core-x' })];
    expect(sortHostsForQuery(hosts, 'core').map((h) => h.id)).toEqual([2, 1]);
    expect(sortHostsForQuery(hosts, '').map((h) => h.id)).toEqual([1, 2]);
  });
});
