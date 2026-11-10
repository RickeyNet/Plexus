import { useId, useState } from 'react';

import { groupLabel } from '@/api/inventory';
import { useInventoryGroups } from '@/api/compliance';
import { useCapacityPlanning, type CapacityPlanningPoint } from '@/api/monitoring';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';

const METRIC_LABELS: Record<string, string> = {
  cpu_percent: 'CPU %',
  memory_percent: 'Memory %',
  route_count: 'Route Count',
  if_up_count: 'Interfaces Up',
  vpn_tunnels_up: 'VPN Tunnels Up',
};

export function CapacityTab() {
  const groups = useInventoryGroups();
  const fid = useId();
  const [metric, setMetric] = useState('cpu_percent');
  const [range, setRange] = useState('90d');
  const [groupId, setGroupId] = useState<number | null>(null);

  const data = useCapacityPlanning({ metric, range, group: groupId, projectionDays: 90, threshold: 80 });
  const points = data.data?.data_points ?? [];
  const projection = data.data?.projection ?? [];
  const estimates = data.data?.threshold_estimates ?? {};

  return (
    <div>
      <div className="toolbar">
        <label className="text-muted" htmlFor={`${fid}-metric`}>Metric:</label>
        <select id={`${fid}-metric`} className="form-select" value={metric} onChange={(e) => setMetric(e.target.value)}>
          {Object.entries(METRIC_LABELS).map(([k, label]) => (
            <option key={k} value={k}>{label}</option>
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
      </div>

      {data.error && !data.data ? (
        <QueryError what="capacity data" query={data} />
      ) : (
        data.isPending && <LoadingState />
      )}

      {data.data && points.length === 0 ? (
        <EmptyState message="No capacity data - run polls to collect metrics." />
      ) : data.data && (
        <div className="stack">
          <div className="card">
            <div style={{ fontWeight: 600, marginBottom: '0.5rem' }}>{METRIC_LABELS[metric] ?? metric}</div>
            <CapacityChart points={points} projection={projection} />
            <div style={{ display: 'flex', gap: '1rem', marginTop: '0.5rem', fontSize: '0.85em' }}>
              <div><span style={{ display: 'inline-block', width: 12, height: 2, background: 'var(--primary)', verticalAlign: 'middle' }} /> Actual</div>
              <div><span style={{ display: 'inline-block', width: 12, height: 2, background: 'var(--warning)', verticalAlign: 'middle', borderTop: '2px dashed var(--warning)' }} /> Projected</div>
            </div>
          </div>

          {Object.keys(estimates).length > 0 && (
            <div className="card">
              <div style={{ fontWeight: 600, marginBottom: '0.5rem' }}>Threshold Estimates</div>
              <table className="data-table table-sm">
                <thead>
                  <tr>
                    <th>Threshold</th>
                    <th>Days Until</th>
                    <th>Est. Date</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(estimates).map(([thresh, info]) => {
                    const days = info.days_until;
                    const color = days != null && days <= 30 ? 'danger' : days != null && days <= 90 ? 'warning' : 'success';
                    return (
                      <tr key={thresh}>
                        <td>{thresh}%</td>
                        <td style={{ color: `var(--${color})`, fontWeight: 600 }}>
                          {days != null ? `${days} days` : 'N/A'}
                        </td>
                        <td>{info.estimated_date ?? 'N/A'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function CapacityChart({ points, projection }: { points: CapacityPlanningPoint[]; projection: CapacityPlanningPoint[] }) {
  const W = 800, H = 300, PAD_L = 50, PAD_R = 20, PAD_T = 20, PAD_B = 40;
  const chartW = W - PAD_L - PAD_R;
  const chartH = H - PAD_T - PAD_B;

  const all = [...points, ...projection];
  if (all.length === 0) return null;

  const values = all.map((p) => p.value).filter((v) => typeof v === 'number');
  const dataMin = Math.min(...values);
  const dataMax = Math.max(...values);
  const yMin = Math.min(0, dataMin);
  const yMax = dataMax + (dataMax - dataMin) * 0.1 || 1;
  const yRange = yMax - yMin || 1;

  const xAt = (i: number) => PAD_L + (i / Math.max(all.length - 1, 1)) * chartW;
  const yAt = (v: number) => PAD_T + chartH - ((v - yMin) / yRange) * chartH;

  const actualPath = points
    .map((p, i) => `${i === 0 ? 'M' : 'L'}${xAt(i).toFixed(1)},${yAt(p.value).toFixed(1)}`)
    .join(' ');
  const projectedPath = projection
    .map((p, i) => {
      const x = xAt(points.length + i);
      return `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${yAt(p.value).toFixed(1)}`;
    })
    .join(' ');

  const gridLines = [];
  for (let i = 0; i <= 4; i++) {
    const y = PAD_T + (i / 4) * chartH;
    const val = yMax - (i / 4) * yRange;
    gridLines.push(
      <g key={i}>
        <line x1={PAD_L} y1={y} x2={W - PAD_R} y2={y} stroke="var(--border)" strokeDasharray="2,2" />
        <text x={PAD_L - 8} y={y + 3} textAnchor="end" fill="var(--text-muted)" fontSize="10">
          {val.toFixed(val < 10 ? 1 : 0)}
        </text>
      </g>,
    );
  }

  const xLabels = [];
  const step = Math.max(1, Math.floor(all.length / 6));
  for (let i = 0; i < all.length; i += step) {
    const label = (all[i].day || all[i].timestamp || '').slice(5, 10);
    xLabels.push(
      <text key={i} x={xAt(i)} y={H - 5} textAnchor="middle" fill="var(--text-muted)" fontSize="10">
        {label}
      </text>,
    );
  }

  return (
    <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet" style={{ width: '100%', height: 'auto' }}>
      {gridLines}
      {xLabels}
      <path d={actualPath} fill="none" stroke="var(--primary)" strokeWidth="2" />
      <path d={projectedPath} fill="none" stroke="var(--warning)" strokeWidth="2" strokeDasharray="6,4" />
    </svg>
  );
}
