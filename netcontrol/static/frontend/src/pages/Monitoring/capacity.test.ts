import { describe, expect, it } from 'vitest';

import type { CapacityHostResult } from '@/api/monitoring';

import {
  fleetDailyAverage,
  fleetProjection,
  formatCapacityValue,
  parseThreshold,
  thresholdEstimates,
} from './capacity';

const host = (hostname: string, over: Partial<CapacityHostResult> = {}): CapacityHostResult => ({
  hostname,
  trend: { slope: 0.1, intercept: 10 },
  projection: [],
  threshold_eta: null,
  ...over,
});

describe('fleetDailyAverage', () => {
  it('averages the hosts of each day and sorts oldest first', () => {
    const rows = [
      { host_id: 1, period_start: '2026-01-02 00:00:00', val_avg: 30 },
      { host_id: 2, period_start: '2026-01-02 00:00:00', val_avg: 50 },
      { host_id: 1, period_start: '2026-01-01 00:00:00', val_avg: 20 },
    ];
    expect(fleetDailyAverage(rows)).toEqual([
      { time: '2026-01-01', value: 20 },
      { time: '2026-01-02', value: 40 },
    ]);
  });

  it('skips rows without a value', () => {
    expect(fleetDailyAverage([{ host_id: 1, period_start: '2026-01-01 00:00:00', val_avg: null }])).toEqual([]);
  });
});

describe('fleetProjection', () => {
  it('averages the per-host projections by date', () => {
    const perHost = [
      host('edge-a', { projection: [{ date: '2026-02-01', value: 60 }, { date: '2026-02-02', value: 62 }] }),
      host('edge-b', { projection: [{ date: '2026-02-01', value: 40 }] }),
      host('edge-c', { trend: null }),
    ];
    expect(fleetProjection(perHost)).toEqual([
      { time: '2026-02-01', value: 50 },
      { time: '2026-02-02', value: 62 },
    ]);
  });
});

describe('thresholdEstimates', () => {
  it('lists only hosts with an estimate, soonest first and undated last', () => {
    const perHost = [
      host('edge-a', { threshold_eta: { date: null, days_until: null, current_value: 10 } }),
      host('edge-b', { threshold_eta: { date: '2026-06-01', days_until: 120, current_value: 55 } }),
      host('edge-c'),
      host('edge-d', { threshold_eta: { date: '2026-03-01', days_until: 28, current_value: 72 } }),
    ];
    expect(thresholdEstimates(perHost).map((e) => e.hostname)).toEqual(['edge-d', 'edge-b', 'edge-a']);
  });
});

describe('formatCapacityValue', () => {
  it('adds a percent sign only to percentage metrics', () => {
    expect(formatCapacityValue('cpu_percent', 80)).toBe('80%');
    expect(formatCapacityValue('route_count', 1200.456)).toBe('1200.46');
  });
});

describe('parseThreshold', () => {
  it('reads a number and treats blank or junk as no threshold', () => {
    expect(parseThreshold(' 85.5 ')).toBe(85.5);
    expect(parseThreshold('')).toBeNull();
    expect(parseThreshold('abc')).toBeNull();
  });
});
