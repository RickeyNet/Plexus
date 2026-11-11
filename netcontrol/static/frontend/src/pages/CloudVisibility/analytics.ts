// View filters and timeline shaping shared by the Flow and Traffic tabs.
import { useState } from 'react';

import type { TimeSeries, TimeSeriesPoint } from '@/lib/echart';
import { parseBackendDate } from '@/lib/datetime';
import { parseBoundedInt } from '@/lib/numberInput';

export const WINDOW_OPTIONS: { hours: number; label: string }[] = [
  { hours: 1, label: 'Last 1 hour' },
  { hours: 6, label: 'Last 6 hours' },
  { hours: 24, label: 'Last 24 hours' },
  { hours: 72, label: 'Last 72 hours' },
  { hours: 168, label: 'Last 7 days' },
];

export const BUCKET_OPTIONS: { minutes: number; label: string }[] = [
  { minutes: 1, label: '1 minute' },
  { minutes: 5, label: '5 minutes' },
  { minutes: 15, label: '15 minutes' },
  { minutes: 30, label: '30 minutes' },
  { minutes: 60, label: '60 minutes' },
];

export const TOP_LIMIT_MIN = 5;
export const TOP_LIMIT_MAX = 200;
const TOP_LIMIT_DEFAULT = 20;

/** Time window, top-list size and timeline bucket of an analytics tab. */
export function useAnalyticsFilters() {
  const [hours, setHours] = useState(24);
  // Raw text, so the field can be cleared and retyped; parsed for the query.
  const [limitText, setLimitText] = useState(String(TOP_LIMIT_DEFAULT));
  const [bucketMinutes, setBucketMinutes] = useState(5);
  const limit = parseBoundedInt(limitText, TOP_LIMIT_MIN, TOP_LIMIT_MAX, TOP_LIMIT_DEFAULT);
  return { hours, setHours, limitText, setLimitText, limit, bucketMinutes, setBucketMinutes };
}

export type AnalyticsFilterState = ReturnType<typeof useAnalyticsFilters>;

/**
 * One chart series from timeline rows. `bucket` is a backend UTC timestamp;
 * it is passed to the chart as an ISO string with its zone so the chart does
 * not read a zone-less value as local time. Rows without a usable bucket are
 * skipped.
 */
export function timelineSeries<T extends { bucket?: string }>(
  name: string,
  rows: T[],
  value: (row: T) => number | undefined,
): TimeSeries {
  const data: TimeSeriesPoint[] = [];
  for (const row of rows) {
    const at = parseBackendDate(row.bucket);
    if (!at) continue;
    data.push({ time: at.toISOString(), value: Number(value(row) ?? 0) || 0 });
  }
  return { name, data };
}
