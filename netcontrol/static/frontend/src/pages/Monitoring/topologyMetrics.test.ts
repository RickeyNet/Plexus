import { describe, expect, it } from 'vitest';

import type { TopologyAvailabilityEntity, TopologyEntityMetricSample } from '@/api/monitoring';

import { entityMetricCharts, formatTraffic, hasEntityMetrics } from './topologyMetrics';

function sample(at: string, values: Partial<TopologyEntityMetricSample>): TopologyEntityMetricSample {
  return { sampled_at: at, latency_ms: null, jitter_ms: null, loss_pct: null, in_bps: null, out_bps: null, ...values };
}

describe('entityMetricCharts', () => {
  it('charts the traffic of a tunnel and nothing else', () => {
    const charts = entityMetricCharts([
      sample('2026-01-01 00:00:00', { in_bps: 1200000, out_bps: 300000 }),
      sample('2026-01-01 01:00:00', { in_bps: 800000, out_bps: 100000 }),
    ]);
    expect(charts.map((c) => c.key)).toEqual(['traffic']);
    expect(charts[0].series.map((s) => s.name)).toEqual(['In', 'Out']);
    expect(charts[0].series[0].data[0]).toEqual({ time: '2026-01-01T00:00:00.000Z', value: 1200000 });
    expect(charts[0].valueFormatter?.(1200000)).toBe('1.2 Mbps');
  });

  it('gives a gateway its latency and loss charts but no empty traffic chart', () => {
    const charts = entityMetricCharts([sample('2026-01-01 00:00:00', { latency_ms: 4.2, jitter_ms: 0.3, loss_pct: 0 })]);
    expect(charts.map((c) => c.key)).toEqual(['delay', 'loss']);
    expect(charts[0].valueFormatter).toBeUndefined();
  });

  it('draws nothing without samples', () => {
    expect(entityMetricCharts([])).toEqual([]);
  });
});

describe('formatTraffic and hasEntityMetrics', () => {
  const entity = { avg_latency_ms: null, avg_in_bps: null, avg_out_bps: null } as unknown as TopologyAvailabilityEntity;

  it('formats the mean rates', () => {
    expect(formatTraffic(1500000, 0)).toBe('1.5 Mbps in / 0 bps out');
    expect(formatTraffic(null, undefined)).toBe('-');
  });

  it('offers measurements only for an entity with any', () => {
    expect(hasEntityMetrics(entity)).toBe(false);
    expect(hasEntityMetrics({ ...entity, avg_in_bps: 0 })).toBe(true);
    expect(hasEntityMetrics({ ...entity, avg_latency_ms: 4.2 })).toBe(true);
  });
});
