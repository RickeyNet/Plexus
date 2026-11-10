import type { CapacityHostResult, CapacityRollupRow } from '@/api/monitoring';
import { formatChartNumber } from '@/lib/chartFormat';
import type { TimeSeriesPoint } from '@/lib/echart';

export interface CapacityMetric {
  label: string;
  /** Suffix of a value of this metric ("%"), empty for a plain count. */
  unit: string;
  /** Threshold preset; null for counts, which have no natural limit. */
  defaultThreshold: number | null;
}

export const CAPACITY_METRICS: Record<string, CapacityMetric> = {
  cpu_percent: { label: 'CPU %', unit: '%', defaultThreshold: 80 },
  memory_percent: { label: 'Memory %', unit: '%', defaultThreshold: 80 },
  route_count: { label: 'Route Count', unit: '', defaultThreshold: null },
  if_up_count: { label: 'Interfaces Up', unit: '', defaultThreshold: null },
  vpn_tunnels_up: { label: 'VPN Tunnels Up', unit: '', defaultThreshold: null },
};

/** A value of `metric` with its unit: 80 -> "80%" for CPU, 1200 -> "1200" for a count. */
export function formatCapacityValue(metric: string, value: number): string {
  return `${formatChartNumber(value)}${CAPACITY_METRICS[metric]?.unit ?? ''}`;
}

/** The threshold typed into the toolbar as a number; null when blank or not a number. */
export function parseThreshold(text: string): number | null {
  const trimmed = text.trim();
  if (!trimmed) return null;
  const n = Number(trimmed);
  return Number.isFinite(n) ? n : null;
}

// Mean of the values of each day, oldest day first.
function averageByDay(samples: { day: string; value: number }[]): TimeSeriesPoint[] {
  const sums = new Map<string, { total: number; count: number }>();
  for (const { day, value } of samples) {
    const entry = sums.get(day) ?? { total: 0, count: 0 };
    entry.total += value;
    entry.count += 1;
    sums.set(day, entry);
  }
  return [...sums.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([day, { total, count }]) => ({ time: day, value: Math.round((total / count) * 100) / 100 }));
}

/** The daily rollups of every host as one series: the per-host average of each day. */
export function fleetDailyAverage(rows: CapacityRollupRow[]): TimeSeriesPoint[] {
  return averageByDay(
    rows.flatMap((r) =>
      typeof r.val_avg === 'number' && r.period_start ? [{ day: r.period_start.slice(0, 10), value: r.val_avg }] : [],
    ),
  );
}

/** The per-host projections as one series: the average projected value of each day. */
export function fleetProjection(perHost: CapacityHostResult[]): TimeSeriesPoint[] {
  return averageByDay(perHost.flatMap((h) => h.projection.map((p) => ({ day: p.date, value: p.value }))));
}

export interface CapacityEstimate {
  hostname: string;
  currentValue: number;
  /** null when the host reaches the threshold too far out to date. */
  daysUntil: number | null;
  date: string | null;
}

/** Hosts trending toward the threshold, soonest first (undated ones last). */
export function thresholdEstimates(perHost: CapacityHostResult[]): CapacityEstimate[] {
  return perHost
    .flatMap((h) =>
      h.threshold_eta
        ? [{
            hostname: h.hostname,
            currentValue: h.threshold_eta.current_value,
            daysUntil: h.threshold_eta.days_until,
            date: h.threshold_eta.date,
          }]
        : [],
    )
    .sort((a, b) => (a.daysUntil ?? Infinity) - (b.daysUntil ?? Infinity) || a.hostname.localeCompare(b.hostname));
}
