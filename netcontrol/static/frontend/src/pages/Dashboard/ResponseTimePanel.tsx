import { useMemo, useState } from 'react';

import { useMetricsQuery } from '@/api/dashboard';
import { TimeSeriesChart } from '@/lib/echart';

type Range = '1h' | '6h' | '24h' | '7d';

const RANGES: { value: Range; label: string }[] = [
  { value: '1h', label: '1h' },
  { value: '6h', label: '6h' },
  { value: '24h', label: '24h' },
  { value: '7d', label: '7d' },
];

export function ResponseTimePanel() {
  const [range, setRange] = useState<Range>('6h');
  const query = useMetricsQuery({ metric: 'response_time_ms', range });

  const { series, avgMs, maxMs } = useMemo(() => {
    const items = query.data?.data ?? [];
    if (!items.length) return { series: [], avgMs: null as number | null, maxMs: null as number | null };

    // Average across hosts per bucket so the panel reflects a single
    // "network response time" trend rather than one line per device.
    const byTime = new Map<string, { sum: number; n: number }>();
    for (const d of items) {
      const t = d.sampled_at ?? d.period_start;
      const v = d.val_avg ?? d.value;
      if (!t || v == null) continue;
      const bucket = byTime.get(t) ?? { sum: 0, n: 0 };
      bucket.sum += v;
      bucket.n += 1;
      byTime.set(t, bucket);
    }
    const points = [...byTime.entries()]
      .map(([time, { sum, n }]) => ({ time, value: sum / n }))
      .sort((a, b) => (a.time < b.time ? -1 : 1));

    const values = points.map((p) => p.value);
    const avg = values.reduce((s, v) => s + v, 0) / (values.length || 1);
    const max = values.length ? Math.max(...values) : 0;

    return {
      series: [{ name: 'Response time (ms)', data: points, color: '#3b82f6' }],
      avgMs: avg,
      maxMs: max,
    };
  }, [query.data]);

  return (
    <div className="glass-card card dashboard-overview-card">
      <div className="dashboard-overview-header">
        <h3 className="dashboard-overview-title">Average Response Time</h3>
        <div className="dashboard-range-tabs" role="tablist" aria-label="Time range">
          {RANGES.map((r) => (
            <button
              key={r.value}
              role="tab"
              aria-selected={range === r.value}
              className={`dashboard-range-tab${range === r.value ? ' active' : ''}`}
              onClick={() => setRange(r.value)}
            >
              {r.label}
            </button>
          ))}
        </div>
      </div>

      <div className="dashboard-response-summary">
        <Stat label="Avg" value={avgMs} />
        <Stat label="Peak" value={maxMs} />
      </div>

      {query.isPending ? (
        <div className="skeleton skeleton-card" style={{ height: 220 }} />
      ) : query.error ? (
        <p style={{ color: 'var(--danger)', margin: 0 }}>
          Failed to load: {(query.error as Error).message}
        </p>
      ) : series.length === 0 ? (
        <div className="dashboard-response-empty">
          <p style={{ margin: 0, color: 'var(--text-muted)' }}>
            No response-time samples yet for this range.
          </p>
        </div>
      ) : (
        <TimeSeriesChart series={series} area yAxisName="ms" height={220} />
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number | null }) {
  return (
    <div className="dashboard-response-stat">
      <span className="dashboard-response-stat-label">{label}</span>
      <span className="dashboard-response-stat-value">
        {value == null ? '-' : `${Math.round(value)} ms`}
      </span>
    </div>
  );
}
