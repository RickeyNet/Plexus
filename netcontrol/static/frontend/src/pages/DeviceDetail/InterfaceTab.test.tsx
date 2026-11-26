import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import type { InterfaceTimeSeriesEntry, InterfaceTimeSeriesResult } from '@/api/deviceDetail';

import { InterfaceTab } from './InterfaceTab';

// Invented rows in the shape GET /api/metrics/interfaces/{id}?range=30d returns:
// bucket averages ordered by if_index then time, plus each interface's newest
// raw sample in `latest`.
function point(over: Partial<InterfaceTimeSeriesEntry>): InterfaceTimeSeriesEntry {
  return {
    if_index: 1,
    if_name: 'Gi1/0/1',
    if_speed_mbps: 1000,
    sampled_at: '2026-01-01 00:00:00',
    in_rate_bps: 0,
    out_rate_bps: 0,
    utilization_pct: 0,
    ...over,
  };
}

const BUCKETED: InterfaceTimeSeriesResult = {
  bucket_seconds: 7200,
  data: [
    point({ if_index: 1, sampled_at: '2026-01-01 00:00:00', in_rate_bps: 1000, out_rate_bps: 500 }),
    point({ if_index: 1, sampled_at: '2026-01-30 22:00:00', in_rate_bps: 2000, out_rate_bps: 500 }),
    point({ if_index: 2, if_name: 'Gi1/0/2', sampled_at: '2026-01-01 00:00:00', in_rate_bps: 9_000_000 }),
    point({ if_index: 2, if_name: 'Gi1/0/2', sampled_at: '2026-01-30 22:00:00', in_rate_bps: 1 }),
  ],
  latest: [
    point({ if_index: 1, sampled_at: '2026-01-30 23:55:00', in_rate_bps: 4_500_000, utilization_pct: 0.5 }),
    point({ if_index: 2, if_name: 'Gi1/0/2', sampled_at: '2026-01-30 23:55:00', in_rate_bps: 2500, utilization_pct: 7 }),
  ],
};

function render(ifData: InterfaceTimeSeriesResult): string {
  return renderToStaticMarkup(<InterfaceTab ifData={ifData} latestPoll={null} />);
}

describe('InterfaceTab', () => {
  it('shows current rates from the newest raw sample, not the last bucket average', () => {
    const html = render(BUCKETED);
    expect(html).toContain('4.50 Mbps');
    expect(html).toContain('2.5 Kbps');
    expect(html).not.toContain('2.0 Kbps');
  });

  it('orders traffic charts by peak activity across the whole series', () => {
    const html = render(BUCKETED);
    const charts = html.slice(html.indexOf('Traffic Charts'));
    expect(charts.indexOf('Gi1/0/2')).toBeGreaterThan(-1);
    expect(charts.indexOf('Gi1/0/2')).toBeLessThan(charts.indexOf('Gi1/0/1'));
  });

  it('falls back to the last ordered row per interface without `latest`', () => {
    const html = render({ data: BUCKETED.data });
    expect(html).toContain('2.0 Kbps');
    expect(html).toContain('1 bps');
  });
});
