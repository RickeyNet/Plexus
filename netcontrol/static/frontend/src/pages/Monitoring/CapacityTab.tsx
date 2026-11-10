import { useId, useMemo, useState } from 'react';

import { groupLabel } from '@/api/inventory';
import { useInventoryGroups } from '@/api/compliance';
import { useCapacityPlanning } from '@/api/monitoring';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { TimeSeriesChart, type TimeSeries } from '@/lib/echart';

import {
  CAPACITY_METRICS,
  fleetDailyAverage,
  fleetProjection,
  formatCapacityValue,
  parseThreshold,
  thresholdEstimates,
} from './capacity';

const PROJECTION_DAYS = 90;

export function CapacityTab() {
  const groups = useInventoryGroups();
  const fid = useId();
  const [metric, setMetric] = useState('cpu_percent');
  const [range, setRange] = useState('90d');
  const [groupId, setGroupId] = useState<number | null>(null);
  // Threshold typed per metric; a metric the user has not touched uses its
  // preset (80 for percentages, none for counts).
  const [thresholdText, setThresholdText] = useState<Record<string, string>>({});

  const meta = CAPACITY_METRICS[metric];
  const thresholdInput = thresholdText[metric] ?? (meta?.defaultThreshold != null ? String(meta.defaultThreshold) : '');
  const threshold = parseThreshold(thresholdInput);

  const query = useCapacityPlanning({ metric, range, group: groupId, projectionDays: PROJECTION_DAYS, threshold });
  const rows = query.data?.data;
  const perHost = query.data?.per_host;

  const actual = useMemo(() => fleetDailyAverage(rows ?? []), [rows]);
  const projected = useMemo(() => fleetProjection(perHost ?? []), [perHost]);
  const estimates = useMemo(() => thresholdEstimates(perHost ?? []), [perHost]);
  const series: TimeSeries[] = useMemo(
    () => [
      { name: 'Actual', data: actual, color: 'var(--primary)' },
      ...(projected.length ? [{ name: 'Projected', data: projected, color: 'var(--warning)', dashed: true }] : []),
    ],
    [actual, projected],
  );
  const chartThreshold = useMemo(
    () => (threshold != null ? { value: threshold, label: `Threshold ${formatCapacityValue(metric, threshold)}` } : undefined),
    [threshold, metric],
  );
  // Keep the threshold line in view when every value is still below it.
  const peak = Math.max(...actual.map((p) => p.value), ...projected.map((p) => p.value));
  const yMax = threshold != null && threshold >= peak ? Math.ceil(threshold * 1.05) : undefined;
  const hostCount = perHost?.length ?? 0;

  return (
    <div>
      <div className="toolbar">
        <label className="text-muted" htmlFor={`${fid}-metric`}>Metric:</label>
        <select id={`${fid}-metric`} className="form-select" value={metric} onChange={(e) => setMetric(e.target.value)}>
          {Object.entries(CAPACITY_METRICS).map(([k, m]) => (
            <option key={k} value={k}>{m.label}</option>
          ))}
        </select>
        {/* Trend projection needs 30d-365d of history; the global bar tops out at 30d. */}
        <label className="text-muted" htmlFor="capacity-history">History:</label>
        <select
          id="capacity-history"
          className="form-select"
          value={range}
          onChange={(e) => setRange(e.target.value)}
          title="History window used to fit the trend (independent of the global time range)"
        >
          <option value="30d">30 days</option>
          <option value="90d">90 days</option>
          <option value="180d">180 days</option>
          <option value="365d">365 days</option>
        </select>
        <label className="text-muted" htmlFor={`${fid}-group`}>Group:</label>
        <select
          id={`${fid}-group`}
          className="form-select"
          value={groupId ?? ''}
          onChange={(e) => setGroupId(e.target.value ? parseInt(e.target.value, 10) : null)}
        >
          <option value="">All Groups</option>
          {(groups.data ?? []).map((g) => (
            <option key={g.id} value={g.id}>{groupLabel(g)}</option>
          ))}
        </select>
        <label className="text-muted" htmlFor={`${fid}-threshold`}>Threshold{meta?.unit ? ` (${meta.unit})` : ''}:</label>
        <input
          id={`${fid}-threshold`}
          className="form-input"
          type="number"
          step="any"
          style={{ width: '7rem' }}
          value={thresholdInput}
          placeholder="None"
          title="Value to estimate a time-to-reach for. Leave blank for no estimate."
          onChange={(e) => setThresholdText((prev) => ({ ...prev, [metric]: e.target.value }))}
        />
      </div>

      {query.error && !query.data ? (
        <QueryError what="capacity data" query={query} />
      ) : (
        query.isPending && <LoadingState />
      )}

      {query.data && actual.length === 0 ? (
        <EmptyState message="No capacity data - run polls to collect metrics." />
      ) : query.data && (
        <div className="stack">
          <div className="card">
            <div style={{ fontWeight: 600 }}>{meta?.label ?? metric}</div>
            <div className="text-muted" style={{ fontSize: '0.85em', marginBottom: '0.5rem' }}>
              Daily average across {hostCount} host{hostCount === 1 ? '' : 's'}, with each host's linear trend
              projected {PROJECTION_DAYS} days ahead.
            </div>
            <TimeSeriesChart
              series={series}
              yAxisName={meta?.unit || undefined}
              unit={meta?.unit}
              yMax={yMax}
              height={300}
              threshold={chartThreshold}
            />
          </div>

          <div className="card">
            <div style={{ fontWeight: 600, marginBottom: '0.5rem' }}>
              Threshold Estimates{threshold != null ? `: ${formatCapacityValue(metric, threshold)}` : ''}
            </div>
            {threshold == null ? (
              <EmptyState compact message="No threshold set" description="Enter a threshold above to estimate when each host reaches it." />
            ) : estimates.length === 0 ? (
              <EmptyState compact message="No host is trending toward this threshold." />
            ) : (
              <DataTable compact>
                <thead>
                  <tr>
                    <th>Host</th>
                    <th style={{ textAlign: 'right' }}>Current</th>
                    <th style={{ textAlign: 'right' }}>Days Until</th>
                    <th>Est. Date</th>
                  </tr>
                </thead>
                <tbody>
                  {estimates.map((e) => {
                    const color = e.daysUntil == null ? 'text-muted' : e.daysUntil <= 30 ? 'danger' : e.daysUntil <= 90 ? 'warning' : 'success';
                    return (
                      <tr key={e.hostname}>
                        <td>{e.hostname}</td>
                        <td style={{ textAlign: 'right' }}>{formatCapacityValue(metric, e.currentValue)}</td>
                        <td style={{ textAlign: 'right', color: `var(--${color})`, fontWeight: 600 }}>
                          {e.daysUntil != null ? `${e.daysUntil} days` : 'Over 100 years'}
                        </td>
                        <td>{e.date ?? '-'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </DataTable>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
