import { describe, expect, it } from 'vitest';

import type { InventoryGroupFull } from '@/api/inventory';

import { countTargetHosts, filterTargetGroups } from './helpers';

const GROUPS: InventoryGroupFull[] = [
  {
    id: 1,
    name: 'Core',
    path: 'Campus / Core',
    hosts: [
      { id: 10, hostname: 'core-sw-01', ip_address: '192.0.2.10', device_type: 'cisco_ios' },
      { id: 11, hostname: 'core-sw-02', ip_address: '192.0.2.11', device_type: 'cisco_nxos' },
    ],
  },
  {
    id: 2,
    name: 'Branch',
    hosts: [
      { id: 20, hostname: 'branch-rtr-01', ip_address: '198.51.100.20', device_type: null },
    ],
  },
  { id: 3, name: 'Empty' },
];

describe('filterTargetGroups', () => {
  it('returns the groups unchanged for a blank search', () => {
    expect(filterTargetGroups(GROUPS, '   ')).toBe(GROUPS);
  });

  it('keeps only the hosts that match on hostname', () => {
    const out = filterTargetGroups(GROUPS, 'SW-02');
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe(1);
    expect(out[0].hosts?.map((h) => h.id)).toEqual([11]);
  });

  it('matches on address and device type', () => {
    expect(filterTargetGroups(GROUPS, '198.51.100').map((g) => g.id)).toEqual([2]);
    expect(filterTargetGroups(GROUPS, 'nxos')[0].hosts?.map((h) => h.id)).toEqual([11]);
  });

  it('keeps every host of a group whose name or path matches', () => {
    expect(filterTargetGroups(GROUPS, 'campus')[0].hosts).toHaveLength(2);
    expect(filterTargetGroups(GROUPS, 'branch')[0].hosts).toHaveLength(1);
  });

  it('drops groups with nothing matching', () => {
    expect(filterTargetGroups(GROUPS, 'no-such-host')).toEqual([]);
  });
});

describe('countTargetHosts', () => {
  it('counts each host once across groups', () => {
    expect(countTargetHosts(GROUPS)).toBe(3);
    expect(countTargetHosts([...GROUPS, { id: 4, name: 'Dup', hosts: GROUPS[1].hosts }])).toBe(3);
  });

  it('is zero with no groups', () => {
    expect(countTargetHosts([])).toBe(0);
  });
});
