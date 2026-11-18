import { describe, expect, it } from 'vitest';

import { addressCount, aggregateUsageLabel, vidRangeLabel, vlanGroupScope } from './ipamModel';

describe('ipamModel helpers', () => {
  it('labels a VLAN id range', () => {
    expect(vidRangeLabel({ min_vid: 100, max_vid: 199 })).toBe('100-199');
    expect(vidRangeLabel({ min_vid: 7, max_vid: 7 })).toBe('7');
    expect(vidRangeLabel({})).toBe('1-4094');
  });

  it('names the scope of a VLAN group', () => {
    expect(vlanGroupScope({ site_id: 3, site_name: 'Branch 1', region_id: null })).toBe('Site Branch 1');
    expect(vlanGroupScope({ site_id: null, region_id: 2, region_name: 'East' })).toBe('Region East');
    expect(vlanGroupScope({ site_id: null, region_id: null })).toBe('Any site');
  });

  it('shortens large address counts', () => {
    expect(addressCount(256)).toBe((256).toLocaleString());
    expect(addressCount(4_294_967_296)).toBe('4.3 billion');
    expect(addressCount(7.9e28)).toBe('7.9e+28');
    expect(addressCount('junk')).toBe('-');
  });

  it('describes aggregate usage', () => {
    expect(aggregateUsageLabel({ utilization_pct: 75, used_addresses: 192, total_addresses: 256 })).toBe(
      '75% (192 of 256 addresses)',
    );
  });
});
