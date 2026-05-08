import { useMemo, useState } from 'react';

import { useInventoryGroups } from '@/api/compliance';
import { useCapacityPlanning } from '@/api/reports';
import { TimeSeriesChart, type TimeSeries } from '@/lib/echart';

const METRICS = [
  { value: 'cpu_percent', label: 'CPU %' },
  { value: 'mem_percent', label: 'Memory %' },
  { value: 'temperature_celsius', label: 'Temperature' },
  { value: 'fan_speed_rpm', label: 'Fan RPM' },
];

const RANGES = [
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: '90d', label: 'Last 90 days' },
  { value: '180d', label: 'Last 180 days' },
];

export function CapacityPlanningTab() {
  const groupsQuery = useInventoryGroups(false);
  const [metric, setMetric] = useState('cpu_percent');
  const [range, setRange] = useState('90d');
  const [group, setGroup] = useState('');

  const data = useCapacityPlanning({ metric, range, group: group || undefined, projectionDays: 30 });

  const isPercent = metric.endsWith('_percent') || metric.endsWith('_pct');

  const series: TimeSeries[] = useMemo(() => {
    if (!data.data?.count) return [];
    const byHost: Record<string, { time: string; value: number }[]> = {};
    for (const d of data.data.data ?? []) {
      const key = d.hostname || `host-${d.host_id}`;
      const arr = byHost[key] ?? (byHost[key] = []);
      arr.push({ time: d.period_start, value: d.val_avg ?? d.value ?? 0 });
    }
    const out: TimeSeries[] = Object.entries(byHost).map(([name, points]) => ({ name, data: points }));
    for (const h of data.data.per_host ?? []) {
      if (h.projection?.length) {
        out.push({
          name: `${h.hostname ?? 'host'} (proj.)`,
          data: h.projection.map((p) => ({ time: p.date, value: p.value })),
        });
      }
    }
    return out;
  }, [data.data]);

  return (
    <div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '0.75rem' }}>
        <div className="form-group" style={{ marginBottom: 0 }}>
          <label className="form-label">Metric</label>
          <select className="form-select" value={metric} onChange={(e) => setMetric(e.target.value)}>
            {METRICS.map((m) => <option key={m.value} value={m.value}>{m.label}</option>)}
          </select>
        </div>
        <div className="form-group" style={{ marginBottom: 0 }}>
          <label className="form-label">Range</label>
          <select className="form-select" value={range} onChange={(e) => setRange(e.target.value)}>
            {RANGES.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
          </select>
        </div>
        <div className="form-group" style={{ marginBottom: 0 }}>
          <label className="form-label">Group</label>
          <select className="form-select" value={group} onChange={(e) => setGroup(e.target.value)}>
            <option value="">All Groups</option>
            {(groupsQuery.data ?? []).map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
          </select>
        </div>
      </div>

      {data.isPending && <p className="text-muted">Loading…</p>}
      {data.error && <p style={{ color: 'var(--danger)' }}>Failed: {(data.error as Error).message}</p>}
      {data.data && !data.data.count && (
        <div className="empty-state">No capacity data yet for this metric.</div>
      )}
      {data.data && !!data.data.count && (
        <>
          <TimeSeriesChart
            series={series}
            yAxisName={isPercent ? '%' : ''}
            yMin={isPercent ? 0 : undefined}
            yMax={isPercent ? 100 : undefined}
            height={320}
          />
          <ThresholdTable result={data.data} isPercent={isPercent} />
        </>
      )}
    </div>
  );
}

function ThresholdTable({ result, isPercent }: { result: NonNullable<ReturnType<typeof useCapacityPlanning>['data']>; isPercent: boolean }) {
  const hosts = result.per_host ?? [];
  const threshold = result.threshold ?? 90;
  if (!hosts.length) return <p className="text-muted">No per-host data available.</p>;
  return (
    <table className="data-table" style={{ marginTop: '0.75rem' }}>
      <thead>
        <tr>
          <th>Host</th>
          <th>Current (avg)</th>
          <th>Trend (per day)</th>
          <th>Threshold ({threshold}{isPercent ? '%' : ''})</th>
          <th>Days Until</th>
        </tr>
      </thead>
      <tbody>
        {hosts.map((h) => {
          const current =
            h.threshold_eta?.current_value ??
            (h.trend ? (h.trend.slope * 90 + h.trend.intercept).toFixed(1) : 'N/A');
          const slopeStr = h.trend ? (h.trend.slope >= 0 ? '+' : '') + h.trend.slope.toFixed(4) : 'N/A';
          const etaStr = h.threshold_eta
            ? `${h.threshold_eta.days_until}d (${h.threshold_eta.date})`
            : h.trend && h.trend.slope <= 0
              ? 'Never (declining)'
              : 'N/A';
          const etaColor =
            h.threshold_eta && h.threshold_eta.days_until < 30
              ? 'var(--danger)'
              : h.threshold_eta && h.threshold_eta.days_until < 90
                ? 'var(--warning)'
                : 'var(--success)';
          return (
            <tr key={h.host_id ?? h.hostname}>
              <td>{h.hostname ?? `Host #${h.host_id}`}</td>
              <td>{typeof current === 'number' ? current.toFixed(1) : current}</td>
              <td>{slopeStr}</td>
              <td>{threshold}{isPercent ? '%' : ''}</td>
              <td style={{ color: etaColor, fontWeight: 600 }}>{etaStr}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
