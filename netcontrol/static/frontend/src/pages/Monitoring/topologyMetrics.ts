import type { TopologyAvailabilityEntity, TopologyEntityMetricSample } from '@/api/monitoring';
import { formatBpsValue } from '@/lib/chartFormat';
import { parseBackendDate } from '@/lib/datetime';
import type { TimeSeries } from '@/lib/echart';

type SampleField = 'latency_ms' | 'jitter_ms' | 'loss_pct' | 'in_bps' | 'out_bps';

/** One chart of an entity's measurements: its series, unit and how values print. */
export interface EntityMetricChart {
  key: 'delay' | 'loss' | 'traffic';
  title: string;
  series: TimeSeries[];
  unit?: string;
  /** Set for the traffic chart: values are bits per second. */
  valueFormatter?: (value: number) => string;
}

const CHARTS: { key: EntityMetricChart['key']; title: string; unit?: string; bps?: boolean; lines: { field: SampleField; name: string; color: string }[] }[] = [
  {
    key: 'delay',
    title: 'Latency and jitter (ms)',
    unit: ' ms',
    lines: [
      { field: 'latency_ms', name: 'Latency', color: 'var(--primary)' },
      { field: 'jitter_ms', name: 'Jitter', color: 'var(--warning)' },
    ],
  },
  {
    key: 'loss',
    title: 'Packet loss (%)',
    unit: '%',
    lines: [{ field: 'loss_pct', name: 'Packet loss', color: 'var(--danger)' }],
  },
  {
    key: 'traffic',
    title: 'Traffic (average between collections)',
    bps: true,
    lines: [
      { field: 'in_bps', name: 'In', color: 'var(--success)' },
      { field: 'out_bps', name: 'Out', color: 'var(--primary)' },
    ],
  },
];

/**
 * The charts of an entity's raw samples: only the series with at least one
 * value, and only the charts with at least one series (an entity without
 * traffic samples gets no traffic chart).
 */
export function entityMetricCharts(samples: TopologyEntityMetricSample[]): EntityMetricChart[] {
  const charts: EntityMetricChart[] = [];
  for (const chart of CHARTS) {
    const series = chart.lines.flatMap((line) => {
      const data = samples.flatMap((s) => {
        const value = s[line.field];
        const at = parseBackendDate(s.sampled_at);
        return typeof value === 'number' && at ? [{ time: at.toISOString(), value }] : [];
      });
      return data.length ? [{ name: line.name, data, color: line.color }] : [];
    });
    if (series.length) {
      charts.push({
        key: chart.key,
        title: chart.title,
        series,
        unit: chart.unit,
        valueFormatter: chart.bps ? formatBpsValue : undefined,
      });
    }
  }
  return charts;
}

/** Whether the vendor measures anything of the entity (its row then offers the measurements). */
export function hasEntityMetrics(e: TopologyAvailabilityEntity): boolean {
  return [e.avg_latency_ms, e.jitter_ms, e.avg_packet_loss_pct, e.avg_in_bps, e.avg_out_bps].some((v) => typeof v === 'number');
}

/** "1.2 Mbps in / 300.0 kbps out", or "-" without traffic samples. */
export function formatTraffic(inBps: number | null | undefined, outBps: number | null | undefined): string {
  if (typeof inBps !== 'number' && typeof outBps !== 'number') return '-';
  const fmt = (v: number | null | undefined) => (typeof v === 'number' ? formatBpsValue(v) : '-');
  return `${fmt(inBps)} in / ${fmt(outBps)} out`;
}
