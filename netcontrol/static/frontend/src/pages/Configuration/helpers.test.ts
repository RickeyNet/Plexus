import { describe, expect, it } from 'vitest';

import type { ConfigDriftEvent } from '@/api/configuration';

import {
  filterDriftEvents,
  formatInterval,
  groupDriftEvents,
  normalizeDiffForGrouping,
  statusColor,
} from './helpers';

const ev = (
  id: number,
  partial: Partial<ConfigDriftEvent>,
): ConfigDriftEvent => ({
  id,
  host_id: id,
  status: 'open',
  ...partial,
});

describe('formatInterval', () => {
  it('formats whole-day intervals', () => {
    expect(formatInterval(86400)).toBe('1d');
    expect(formatInterval(86400 * 7)).toBe('7d');
  });

  it('formats whole-hour intervals', () => {
    expect(formatInterval(3600)).toBe('1h');
    expect(formatInterval(3600 * 6)).toBe('6h');
  });

  it('returns dash for null/zero', () => {
    expect(formatInterval(null)).toBe('-');
    expect(formatInterval(0)).toBe('-');
  });
});

describe('statusColor', () => {
  it('maps known statuses', () => {
    expect(statusColor('open')).toBe('var(--danger)');
    expect(statusColor('accepted')).toBe('var(--warning)');
    expect(statusColor('resolved')).toBe('var(--success)');
  });

  it('defaults to success for unknown', () => {
    expect(statusColor(null)).toBe('var(--success)');
  });
});

describe('normalizeDiffForGrouping', () => {
  it('strips diff headers and hunks', () => {
    const diff = `--- a/host1\n+++ b/host1\n@@ -1,3 +1,3 @@\n context\n-old\n+new`;
    expect(normalizeDiffForGrouping(diff)).toBe('context\n-old\n+new');
  });

  it('handles empty input', () => {
    expect(normalizeDiffForGrouping(null)).toBe('');
    expect(normalizeDiffForGrouping('')).toBe('');
  });
});

describe('groupDriftEvents', () => {
  it('groups events with identical normalized diffs', () => {
    const a = ev(1, { diff_text: '--- a/h1\n+++ b/h1\n+new line' });
    const b = ev(2, { diff_text: '--- a/h2\n+++ b/h2\n+new line' });
    const c = ev(3, { diff_text: '+different change' });
    const groups = groupDriftEvents([a, b, c]);
    expect(groups).toHaveLength(2);
    expect(groups[0].events).toHaveLength(2);
    expect(groups[1].events).toHaveLength(1);
  });
});

describe('filterDriftEvents', () => {
  const events = [
    ev(1, { hostname: 'core-sw1', ip_address: '10.0.0.1' }),
    ev(2, { hostname: 'edge-rtr', ip_address: '10.0.0.2', device_type: 'cisco_ios' }),
  ];

  it('returns all events when query is empty', () => {
    expect(filterDriftEvents(events, '')).toHaveLength(2);
  });

  it('filters by hostname', () => {
    expect(filterDriftEvents(events, 'core')).toHaveLength(1);
  });

  it('filters by device type', () => {
    expect(filterDriftEvents(events, 'cisco')).toHaveLength(1);
  });

  it('is case-insensitive', () => {
    expect(filterDriftEvents(events, 'CORE-SW1')).toHaveLength(1);
  });
});
