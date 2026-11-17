import { describe, expect, it } from 'vitest';

import { EMPTY_CUSTOM_DATA_FILTER } from './customData';
import {
  criteriaCount,
  describeFilter,
  draftToFilter,
  EMPTY_DRAFT,
  filterKey,
  filterToDraft,
  inventoryFilterToDraft,
  splitList,
  type DynamicGroupFilter,
} from './dynamicGroupFilter';
import { NONE } from './deviceModel';

describe('splitList', () => {
  it('splits on commas and whitespace, trims and drops repeats', () => {
    expect(splitList(' 192.0.2.0/24, 198.51.100.0/24\n192.0.2.0/24 ,, ')).toEqual(['192.0.2.0/24', '198.51.100.0/24']);
    expect(splitList('')).toEqual([]);
  });
});

describe('draftToFilter', () => {
  it('leaves out empty criteria', () => {
    expect(draftToFilter(EMPTY_DRAFT)).toEqual({});
    expect(criteriaCount(draftToFilter(EMPTY_DRAFT))).toBe(0);
  });

  it('maps every criterion to the wire format', () => {
    const filter = draftToFilter({
      groups: [3, 4],
      includeSubgroups: false,
      data: { tagIds: [7], fields: { tier: 'gold', owner: '*' }, device: { role: [2, NONE], site: [9] } },
      tagMatch: 'any',
      platforms: 'Cisco_IOS, juniper_junos',
      statuses: ['down'],
      searchMode: 'regex',
      searchValue: ' ^access- ',
      prefixes: '192.0.2.0/24 2001:db8::/32',
    });
    expect(filter).toEqual({
      groups: [3, 4],
      include_subgroups: false,
      role_id: [2, null],
      site_id: [9],
      platforms: ['cisco_ios', 'juniper_junos'],
      statuses: ['down'],
      tag_ids: [7],
      tag_match: 'any',
      custom_fields: { tier: ['gold'], owner: ['*'] },
      search: { mode: 'regex', value: '^access-' },
      prefixes: ['192.0.2.0/24', '2001:db8::/32'],
    });
    // include_subgroups and tag_match qualify other criteria; they do not count.
    expect(criteriaCount(filter)).toBe(9);
  });

  it('round-trips through filterToDraft', () => {
    const filter: DynamicGroupFilter = {
      groups: [1],
      include_subgroups: true,
      manufacturer_id: [null, 5],
      tag_ids: [2, 3],
      tag_match: 'all',
      custom_fields: { tier: ['gold'] },
      search: { mode: 'contains', value: 'sw' },
      prefixes: ['203.0.113.0/24'],
    };
    expect(draftToFilter(filterToDraft(filter))).toEqual(filter);
  });

  it('carries the region and tenant facets as region_id and tenant_id', () => {
    const filter = draftToFilter({ ...EMPTY_DRAFT, data: { tagIds: [], fields: {}, device: { region: [4], tenant: [NONE, 2] } } });
    expect(filter).toEqual({ region_id: [4], tenant_id: [null, 2] });
    expect(draftToFilter(filterToDraft(filter))).toEqual(filter);
  });
});

describe('inventoryFilterToDraft', () => {
  it('keeps the Filter menu value and requires every tag, as the menu does', () => {
    const data = { tagIds: [1, 2], fields: {}, device: { lifecycle_status: [4] } };
    const filter = draftToFilter(inventoryFilterToDraft(data, ' core '));
    expect(filter).toEqual({
      lifecycle_status_id: [4],
      tag_ids: [1, 2],
      tag_match: 'all',
      search: { mode: 'contains', value: 'core' },
    });
  });

  it('gives an empty definition for no filter and no search', () => {
    expect(criteriaCount(draftToFilter(inventoryFilterToDraft(EMPTY_CUSTOM_DATA_FILTER, '  ')))).toBe(0);
  });
});

describe('filterKey and describeFilter', () => {
  it('keys ignore property order', () => {
    expect(filterKey({ platforms: ['a'], statuses: ['up'] })).toBe(filterKey({ statuses: ['up'], platforms: ['a'] }));
    expect(filterKey({ platforms: ['a'] })).not.toBe(filterKey({ platforms: ['b'] }));
  });

  it('describes each criterion', () => {
    expect(describeFilter({})).toBe('No criteria');
    expect(
      describeFilter({ groups: [1, 2], role_id: [3], tag_ids: [1], tag_match: 'any', prefixes: ['192.0.2.0/24'] }),
    ).toBe('2 groups (with sub-groups) · role (1) · tags (any of 1) · in 192.0.2.0/24');
    expect(describeFilter({ custom_fields: { owner: ['*'] }, search: { mode: 'regex', value: '^sw' } })).toBe(
      'owner set · name ~ /^sw/',
    );
  });
});
