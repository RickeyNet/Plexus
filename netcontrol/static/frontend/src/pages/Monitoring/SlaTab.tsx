import { useState } from 'react';

import { Modal } from '@/components/Modal';
import { TabBar } from '@/components/TabBar';
import {
  useSlaCompliance,
  useSlaComplianceHistory,
  useSlaHostDetail,
  useSlaSummary,
  type SlaComplianceCounts,
  type SlaDailyPoint,
  type SlaHostSummary,
} from '@/api/monitoring';
import { formatMinutes, formatTimestamp, slaStatusBadge } from './helpers';

type SubTab = 'hosts' | 'trends';

const SUB_TABS: { key: SubTab; label: string }[] = [
  { key: 'hosts', label: 'Host SLAs' },
  { key: 'trends', label: 'Trends' },
];

export function SlaTab() {
  const [days, setDays] = useState(30);
  const [subTab, setSubTab] = useState<SubTab>('hosts');
  const summary = useSlaSummary(days);
  const [hostQuery, setHostQuery] = useState('');
  const [detailHostId, setDetailHostId] = useState<number | null>(null);

  return (
    <div>
      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap' }}>
        <label className="text-muted">Period:</label>
        <select className="form-select" value={days} onChange={(e) => setDays(parseInt(e.target.value, 10))}>
          <option value={7}>Last 7 days</option>
          <option value={30}>Last 30 days</option>
          <option value={90}>Last 90 days</option>
          <option value={365}>Last 365 days</option>
        </select>
      </div>

      <SlaComplianceStrip compliance={summary.data?.compliance} />

      <SlaGauges summary={summary.data} />

      <TabBar tabs={SUB_TABS} active={subTab} onChange={setSubTab} size="sm" aria-label="SLA views" />

      {subTab === 'hosts' && (
        <>
          <input
            className="form-input"
            placeholder="Search hosts…"
            value={hostQuery}
            onChange={(e) => setHostQuery(e.target.value)}
            style={{ marginBottom: '0.5rem' }}
          />
          <SlaHostsList
            summary={summary.data}
            query={hostQuery}
            onSelect={setDetailHostId}
          />
          <SlaIncidents summary={summary.data} />
        </>
      )}
      {subTab === 'trends' && <SlaTrends summary={summary.data} days={days} />}

      {detailHostId != null && (
        <SlaHostDetailModal
          hostId={detailHostId}
          days={days}
          onClose={() => setDetailHostId(null)}
        />
      )}
    </div>
  );
}

// Hosts per worst SLA target status, as evaluated on the server (hourly, or
// on demand from Configure -> SLA Targets). Target windows are set per target
// and are independent of the Period selector.
function SlaComplianceStrip({ compliance }: { compliance?: SlaComplianceCounts }) {
  if (!compliance || compliance.hosts === 0) {
    return (
      <div className="card text-muted" style={{ padding: '0.6rem 1rem', marginBottom: '0.75rem', fontSize: '0.9em' }}>
        No SLA target has been evaluated yet. Define targets under Configure, SLA Targets.
      </div>
    );
  }
  const items: { key: 'met' | 'warn' | 'breach' | 'no_data'; color: string }[] = [
    { key: 'met', color: 'var(--success)' },
    { key: 'warn', color: 'var(--warning)' },
    { key: 'breach', color: 'var(--danger)' },
    { key: 'no_data', color: 'var(--text-muted)' },
  ];
  return (
    <div className="card" style={{ padding: '0.6rem 1rem', marginBottom: '0.75rem', display: 'flex', gap: '1.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
      <strong>SLA compliance</strong>
      {items.map(({ key, color }) => (
        <div key={key}>
          <span className="text-muted">{slaStatusBadge(key).label}:</span>{' '}
          <strong style={{ color }}>{compliance[key]}</strong>
        </div>
      ))}
      <div className="text-muted" style={{ fontSize: '0.85em', marginLeft: 'auto' }}>
        {compliance.hosts} host{compliance.hosts === 1 ? '' : 's'} with targets, evaluated {formatTimestamp(compliance.evaluated_at)}
      </div>
    </div>
  );
}

const CIRC = 2 * Math.PI * 52;

function Gauge({ value, label, scale, format }: { value: number | null | undefined; label: string; scale: number; format: (v: number) => string }) {
  const v = value ?? 0;
  const pct = Math.min(v / scale, 1);
  return (
    <div className="card" style={{ padding: '0.75rem', textAlign: 'center', minWidth: 130 }}>
      <svg viewBox="0 0 120 120" width="100" height="100">
        <circle cx="60" cy="60" r="52" fill="none" stroke="var(--bg-secondary)" strokeWidth="10" />
        <circle
          cx="60"
          cy="60"
          r="52"
          fill="none"
          stroke="var(--primary)"
          strokeWidth="10"
          strokeDasharray={`${pct * CIRC} ${CIRC}`}
          strokeDashoffset={CIRC / 4}
          transform="rotate(-90 60 60)"
          strokeLinecap="round"
        />
      </svg>
      <div style={{ fontSize: '1.1em', fontWeight: 600 }}>{value != null ? format(v) : '-'}</div>
      <div className="text-muted" style={{ fontSize: '0.8em' }}>{label}</div>
    </div>
  );
}

function SlaGauges({ summary }: { summary?: { avg_uptime_pct?: number | null; avg_latency_ms?: number | null; avg_jitter_ms?: number | null; avg_packet_loss_pct?: number | null; mttr_minutes?: number | null; mttd_minutes?: number | null } }) {
  return (
    <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginBottom: '0.75rem', alignItems: 'center' }}>
      <Gauge value={summary?.avg_uptime_pct} label="Avg Uptime" scale={100} format={(v) => `${v.toFixed(2)}%`} />
      <Gauge value={summary?.avg_latency_ms} label="Avg Latency" scale={500} format={(v) => `${v.toFixed(1)}ms`} />
      <Gauge value={summary?.avg_jitter_ms} label="Avg Jitter" scale={100} format={(v) => `${v.toFixed(1)}ms`} />
      <Gauge value={summary?.avg_packet_loss_pct} label="Avg Pkt Loss" scale={100} format={(v) => `${v.toFixed(2)}%`} />
      <div className="card" style={{ padding: '0.75rem', minWidth: 110 }}>
        <div className="text-muted" style={{ fontSize: '0.8em' }}>MTTR</div>
        <div style={{ fontWeight: 600, fontSize: '1.1em' }}>{formatMinutes(summary?.mttr_minutes)}</div>
        <div className="text-muted" style={{ fontSize: '0.8em', marginTop: '0.4rem' }}>MTTD</div>
        <div style={{ fontWeight: 600, fontSize: '1.1em' }}>{formatMinutes(summary?.mttd_minutes)}</div>
      </div>
    </div>
  );
}

function SlaHostsList({
  summary,
  query,
  onSelect,
}: {
  summary?: { hosts: SlaHostSummary[] };
  query: string;
  onSelect: (id: number) => void;
}) {
  const hosts = summary?.hosts ?? [];
  const q = query.trim().toLowerCase();
  const filtered = q
    ? hosts.filter((h) => (h.hostname ?? '').toLowerCase().includes(q) || (h.ip_address ?? '').toLowerCase().includes(q))
    : hosts;

  if (filtered.length === 0) {
    return <div className="empty-state">No SLA data available - run monitoring polls to collect metrics.</div>;
  }
  return (
    <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 1fr 1fr 1fr', padding: '0.5rem 1rem', background: 'var(--bg-secondary)', fontSize: '0.85em', fontWeight: 600 }}>
        <div>Host</div>
        <div>Uptime</div>
        <div>Latency</div>
        <div>Jitter</div>
        <div>Pkt Loss</div>
        <div>Status</div>
      </div>
      {filtered.map((h) => {
        const uptimeColor = (h.uptime_pct ?? 0) >= 99.9 ? 'success' : (h.uptime_pct ?? 0) >= 99 ? 'warning' : 'danger';
        const badge = slaStatusBadge(h.sla_status);
        return (
          <div
            key={h.host_id}
            style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 1fr 1fr 1fr', padding: '0.5rem 1rem', borderTop: '1px solid var(--border-color)', cursor: 'pointer', fontSize: '0.9em' }}
            onClick={() => onSelect(h.host_id)}
          >
            <div>
              <strong>{h.hostname}</strong>
              <span className="text-muted" style={{ fontSize: '0.8em', marginLeft: '0.4rem' }}>{h.ip_address}</span>
            </div>
            <div style={{ color: `var(--${uptimeColor})`, fontWeight: 600 }}>{h.uptime_pct != null ? `${h.uptime_pct.toFixed(2)}%` : '-'}</div>
            <div>{h.avg_latency_ms != null ? `${h.avg_latency_ms.toFixed(1)}ms` : '-'}</div>
            <div>{h.jitter_ms != null ? `${h.jitter_ms.toFixed(1)}ms` : '-'}</div>
            <div>{h.avg_packet_loss_pct != null ? `${h.avg_packet_loss_pct.toFixed(2)}%` : '-'}</div>
            <div>
              <span className={badge.cls}>{badge.label}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function SlaIncidents({ summary }: { summary?: { total_alerts?: number; resolved_alerts?: number; mttr_minutes?: number | null; mttd_minutes?: number | null } }) {
  const total = summary?.total_alerts ?? 0;
  const resolved = summary?.resolved_alerts ?? 0;
  const open = total - resolved;
  return (
    <div className="card" style={{ padding: '1rem', marginTop: '0.75rem' }}>
      <div style={{ display: 'flex', gap: '2rem', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
        <div><span className="text-muted">Total Alerts:</span> <strong>{total}</strong></div>
        <div><span className="text-muted">Resolved:</span> <strong style={{ color: 'var(--success)' }}>{resolved}</strong></div>
        <div><span className="text-muted">Open:</span> <strong style={{ color: open > 0 ? 'var(--danger)' : 'var(--success)' }}>{open}</strong></div>
        <div><span className="text-muted">Avg MTTR:</span> <strong>{formatMinutes(summary?.mttr_minutes)}</strong></div>
        <div><span className="text-muted">Avg MTTD:</span> <strong>{formatMinutes(summary?.mttd_minutes)}</strong></div>
      </div>
      <div className="text-muted" style={{ fontSize: '0.85em' }}>
        <p><strong>MTTR</strong> (Mean Time To Repair): time from alert to acknowledgement.</p>
        <p><strong>MTTD</strong> (Mean Time To Detect): time from first failure to alert creation.</p>
      </div>
    </div>
  );
}

function SlaTrends({ summary, days }: { summary?: { hosts: SlaHostSummary[] }; days: number }) {
  const firstHostId = summary?.hosts?.[0]?.host_id ?? null;
  const detail = useSlaHostDetail(firstHostId, days);
  if (!firstHostId) {
    return <div className="card text-muted" style={{ padding: '1rem' }}>No trend data available.</div>;
  }
  if (detail.isPending) return <div className="text-muted">Loading…</div>;
  if (detail.error) return <div style={{ color: 'var(--danger)' }}>Error: {(detail.error as Error).message}</div>;
  const daily = detail.data?.daily ?? [];
  return (
    <div>
      <SlaChart daily={daily} field="uptime_pct" label="Uptime %" color="var(--success)" minY={95} maxY={100} />
      <SlaChart daily={daily} field="avg_latency_ms" label="Latency (ms)" color="var(--primary)" minY={0} maxY={null} />
      <SlaChart daily={daily} field="jitter_ms" label="Jitter (ms)" color="var(--warning)" minY={0} maxY={null} />
      <SlaChart daily={daily} field="avg_packet_loss_pct" label="Packet Loss %" color="var(--danger)" minY={0} maxY={null} />
      <div className="text-muted" style={{ fontSize: '0.8em', marginTop: '0.5rem' }}>
        Showing trends for <strong>{detail.data?.hostname}</strong>. Click a host to view its specific trends.
      </div>
    </div>
  );
}

function SlaChart({
  daily,
  field,
  label,
  color,
  minY,
  maxY,
}: {
  daily: SlaDailyPoint[];
  field: keyof SlaDailyPoint;
  label: string;
  color: string;
  minY: number | null;
  maxY: number | null;
}) {
  const W = 700, H = 200, PAD_L = 55, PAD_R = 20, PAD_T = 30, PAD_B = 35;
  const chartW = W - PAD_L - PAD_R;
  const chartH = H - PAD_T - PAD_B;

  const values = daily.map((d) => d[field]).filter((v): v is number => typeof v === 'number');
  if (values.length === 0) {
    return (
      <div className="card" style={{ padding: '1rem', marginBottom: '0.75rem' }}>
        <div style={{ fontWeight: 600 }}>{label}</div>
        <div className="text-muted">No data</div>
      </div>
    );
  }

  const dataMin = Math.min(...values);
  const dataMax = Math.max(...values);
  const yMin = minY != null ? Math.min(minY, dataMin) : dataMin - (dataMax - dataMin) * 0.1;
  const yMax = maxY != null ? Math.max(maxY, dataMax) : dataMax + (dataMax - dataMin) * 0.1 || 1;
  const yRange = yMax - yMin || 1;

  const points = daily
    .map((d, i) => {
      const v = d[field];
      if (typeof v !== 'number') return null;
      const x = PAD_L + (i / Math.max(daily.length - 1, 1)) * chartW;
      const y = PAD_T + chartH - ((v - yMin) / yRange) * chartH;
      return { x, y, v, day: d.day };
    })
    .filter((p): p is { x: number; y: number; v: number; day: string } => p != null);

  if (points.length === 0) return null;

  const linePath = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
  const areaPath = `${linePath} L${points[points.length - 1].x.toFixed(1)},${PAD_T + chartH} L${points[0].x.toFixed(1)},${PAD_T + chartH} Z`;

  const gridLines = [];
  for (let i = 0; i <= 4; i++) {
    const y = PAD_T + (i / 4) * chartH;
    const val = yMax - (i / 4) * yRange;
    gridLines.push(
      <g key={i}>
        <line x1={PAD_L} y1={y} x2={W - PAD_R} y2={y} stroke="var(--border-color)" strokeDasharray="2,2" />
        <text x={PAD_L - 8} y={y + 3} textAnchor="end" fill="var(--text-muted)" fontSize="10">
          {val.toFixed(val < 10 ? 1 : 0)}
        </text>
      </g>,
    );
  }

  const xLabels = [];
  const step = Math.max(1, Math.floor(daily.length / 5));
  for (let i = 0; i < daily.length; i += step) {
    const x = PAD_L + (i / Math.max(daily.length - 1, 1)) * chartW;
    xLabels.push(
      <text key={i} x={x} y={H - 5} textAnchor="middle" fill="var(--text-muted)" fontSize="10">
        {(daily[i].day || '').slice(5)}
      </text>,
    );
  }

  return (
    <div className="card" style={{ padding: '1rem', marginBottom: '0.75rem' }}>
      <div style={{ fontWeight: 600, marginBottom: '0.5rem' }}>{label}</div>
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet" style={{ width: '100%', height: 'auto' }}>
        {gridLines}
        {xLabels}
        <path d={areaPath} fill={color} opacity="0.15" />
        <path d={linePath} fill="none" stroke={color} strokeWidth="2" />
        {points.map((p, i) => (
          <circle key={i} cx={p.x} cy={p.y} r="3" fill="white" stroke={color} strokeWidth="2">
            <title>{`${p.day}: ${p.v.toFixed(2)}`}</title>
          </circle>
        ))}
      </svg>
    </div>
  );
}

function SlaHostDetailModal({ hostId, days, onClose }: { hostId: number; days: number; onClose: () => void }) {
  const detail = useSlaHostDetail(hostId, days);
  return (
    <Modal isOpen onClose={onClose} title={`SLA Detail: ${detail.data?.hostname ?? `Host #${hostId}`}`} size="large">
      {detail.isPending && <div className="text-muted">Loading…</div>}
      {detail.error && <div style={{ color: 'var(--danger)' }}>Error: {(detail.error as Error).message}</div>}
      {detail.data && (
        <>
          <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap', marginBottom: '1rem', fontSize: '0.9em' }}>
            <div><span className="text-muted">Host:</span> <strong>{detail.data.hostname}</strong></div>
            <div><span className="text-muted">IP:</span> {detail.data.ip_address}</div>
            <div><span className="text-muted">Type:</span> {detail.data.device_type ?? '-'}</div>
            <div><span className="text-muted">Period:</span> {detail.data.period_days} days</div>
            <div><span className="text-muted">Alerts:</span> {detail.data.total_alerts} ({detail.data.resolved_alerts} resolved)</div>
            <div><span className="text-muted">MTTR:</span> {formatMinutes(detail.data.mttr_minutes)}</div>
          </div>
          <SlaHostTargets hostId={hostId} />
          {detail.data.daily && detail.data.daily.length > 0 ? (
            <>
              <SlaChart daily={detail.data.daily} field="uptime_pct" label="Daily Uptime %" color="var(--success)" minY={95} maxY={100} />
              <SlaChart daily={detail.data.daily} field="avg_latency_ms" label="Daily Latency (ms)" color="var(--primary)" minY={0} maxY={null} />
              <SlaChart daily={detail.data.daily} field="jitter_ms" label="Daily Jitter (ms)" color="var(--warning)" minY={0} maxY={null} />
              <SlaChart daily={detail.data.daily} field="avg_packet_loss_pct" label="Daily Packet Loss %" color="var(--danger)" minY={0} maxY={null} />
            </>
          ) : (
            <div className="text-muted">No daily trend data available.</div>
          )}
        </>
      )}
    </Modal>
  );
}

const SLA_METRIC_UNITS: Record<string, string> = { uptime: '%', latency: ' ms', jitter: ' ms', packet_loss: '%' };

function formatSlaValue(metric: string, value: number | null | undefined): string {
  if (value == null) return '-';
  return `${value.toFixed(metric === 'uptime' ? 3 : 2)}${SLA_METRIC_UNITS[metric] ?? ''}`;
}

// The host's SLA targets as last evaluated on the server, and the recent
// status changes.
function SlaHostTargets({ hostId }: { hostId: number }) {
  const compliance = useSlaCompliance(hostId);
  const history = useSlaComplianceHistory(hostId, 10);
  const rows = compliance.data ?? [];
  const changes = history.data ?? [];
  if (rows.length === 0 && changes.length === 0) return null;
  return (
    <div className="card" style={{ padding: '0.75rem 1rem', marginBottom: '1rem' }}>
      <div style={{ fontWeight: 600, marginBottom: '0.5rem' }}>SLA targets</div>
      {rows.length > 0 && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Target</th>
              <th>Value</th>
              <th>Target / Warning</th>
              <th>Window</th>
              <th>Status</th>
              <th>Since</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const badge = slaStatusBadge(r.status);
              return (
                <tr key={r.target_id}>
                  <td>{r.target_name}</td>
                  <td>{formatSlaValue(r.metric, r.value)}</td>
                  <td>{formatSlaValue(r.metric, r.target_value)} / {formatSlaValue(r.metric, r.warning_value)}</td>
                  <td>{r.window_days} days</td>
                  <td><span className={badge.cls}>{badge.label}</span></td>
                  <td>{formatTimestamp(r.status_since)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {changes.length > 0 && (
        <>
          <div className="text-muted" style={{ fontSize: '0.85em', margin: '0.75rem 0 0.25rem' }}>Recent status changes</div>
          {changes.map((c) => (
            <div key={c.id} style={{ fontSize: '0.85em', display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
              <span className="text-muted">{formatTimestamp(c.evaluated_at)}</span>
              <span>{c.target_name}:</span>
              {c.previous_status && <span className={slaStatusBadge(c.previous_status).cls}>{slaStatusBadge(c.previous_status).label}</span>}
              {c.previous_status && <span className="text-muted">to</span>}
              <span className={slaStatusBadge(c.status).cls}>{slaStatusBadge(c.status).label}</span>
              <span className="text-muted">{formatSlaValue(c.metric, c.value)}</span>
            </div>
          ))}
        </>
      )}
    </div>
  );
}
