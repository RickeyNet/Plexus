import { describe, expect, it } from 'vitest';

import { timelineSeries } from './analytics';

describe('timelineSeries', () => {
  it('reads zone-less and offset buckets as UTC and keeps the zone in the chart time', () => {
    const series = timelineSeries(
      'Bytes',
      [
        { bucket: '2026-07-07 12:00:00', total_bytes: 1024 },
        { bucket: '2026-07-07 12:05:00+00', total_bytes: 2048 },
      ],
      (r) => r.total_bytes,
    );
    expect(series.name).toBe('Bytes');
    expect(series.data).toEqual([
      { time: '2026-07-07T12:00:00.000Z', value: 1024 },
      { time: '2026-07-07T12:05:00.000Z', value: 2048 },
    ]);
  });

  it('skips rows without a usable bucket and zeroes missing values', () => {
    const series = timelineSeries(
      'Total',
      [
        { bucket: undefined, total_value: 5 },
        { bucket: 'not-a-date', total_value: 6 },
        { bucket: '2026-07-07T12:00:00Z', total_value: undefined },
      ],
      (r) => r.total_value,
    );
    expect(series.data).toEqual([{ time: '2026-07-07T12:00:00.000Z', value: 0 }]);
  });
});
