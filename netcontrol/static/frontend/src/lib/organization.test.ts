import { describe, expect, it } from 'vitest';

import { siteStatusLabel, siteStatusTone, tenantCountRows, treeOptions } from './organization';

const NBSP2 = '  ';

const REGIONS = [
  { id: 1, parent_id: null, name: 'Europe', depth: 0 },
  { id: 2, parent_id: 1, name: 'West', depth: 1 },
  { id: 3, parent_id: 2, name: 'Netherlands', depth: 2 },
  { id: 4, parent_id: null, name: 'Asia', depth: 0 },
];

describe('treeOptions', () => {
  it('indents each node by its depth, in the given order', () => {
    expect(treeOptions(REGIONS).map((o) => o.label)).toEqual([
      'Europe',
      `${NBSP2}West`,
      `${NBSP2}${NBSP2}Netherlands`,
      'Asia',
    ]);
  });

  it('leaves out a node and everything under it (the parents it may move under)', () => {
    expect(treeOptions(REGIONS, 2).map((o) => o.value)).toEqual([1, 4]);
    expect(treeOptions(REGIONS, 1).map((o) => o.value)).toEqual([4]);
    expect(treeOptions(REGIONS, null).map((o) => o.value)).toEqual([1, 2, 3, 4]);
  });
});

describe('site status', () => {
  it('labels and tones the statuses, passing unknown ones through', () => {
    expect(siteStatusLabel('decommissioning')).toBe('Decommissioning');
    expect(siteStatusLabel('')).toBe('Active');
    expect(siteStatusLabel('mothballed')).toBe('mothballed');
    expect(siteStatusTone('planned')).toBe('info');
    expect(siteStatusTone('retired')).toBe('neutral');
    expect(siteStatusTone('active')).toBe('success');
  });
});

describe('tenantCountRows', () => {
  it('orders the known kinds first and makes later tables readable', () => {
    const rows = tenantCountRows({ virtual_machines: 2, vrfs: 1, hosts: 3, circuits: 0, prefixes: 4 });
    expect(rows.map((r) => [r.label, r.count])).toEqual([
      ['Hosts', 3],
      ['Prefixes', 4],
      ['VRFs', 1],
      ['Circuits', 0],
      ['Virtual machines', 2],
    ]);
    expect(tenantCountRows(undefined)).toEqual([]);
  });
});
