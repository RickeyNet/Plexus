import { useEffect, useMemo, useState, type FormEvent } from 'react';

import { Modal } from '@/components/Modal';
import { useInventoryGroupsFull } from '@/api/inventory';
import {
  useCreateSlaTarget,
  useDeleteSlaTarget,
  useSlaHostDetail,
  useSlaSummary,
  useSlaTargets,
  useUpdateSlaTarget,
  type SlaDailyPoint,
  type SlaHostSummary,
  type SlaTarget,
  type SlaTargetCreate,
} from '@/api/monitoring';
import { formatMinutes, getHostSlaCompliance } from './helpers';

type SubTab = 'hosts' | 'trends' | 'targets';

const METRIC_LABELS: Record<string, string> = {
  uptime: 'Uptime %',
  latency: 'Latency (ms)',
  jitter: 'Jitter (ms)',
  packet_loss: 'Packet Loss %',
};

export function SlaTab() {
  const [days, setDays] = useState(30);
  const [subTab, setSubTab] = useState<SubTab>('hosts');
  const summary = useSlaSummary(days);
  const targets = useSlaTargets();
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
        </select>
      </div>

      <SlaGauges summary={summary.data} />

      <div className="tab-bar" role="tablist" style={{ marginBottom: '0.75rem' }}>
        {(['hosts', 'trends', 'targets'] as SubTab[]).map((t) => (
          <button
            key={t}
            role="tab"
            aria-selected={subTab === t}
            className={`tab-btn${subTab === t ? ' active' : ''}`}
            onClick={() => setSubTab(t)}
          >
            {t === 'hosts' ? 'Host SLAs' : t === 'trends' ? 'Trends' : 'Targets'}
          </button>
        ))}
      </div>

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
            targets={targets.data ?? []}
            query={hostQuery}
            onSelect={setDetailHostId}
          />
          <SlaIncidents summary={summary.data} />
        </>
      )}
      {subTab === 'trends' && <SlaTrends summary={summary.data} days={days} />}
      {subTab === 'targets' && <SlaTargetsTab targets={targets.data ?? []} />}

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
  targets,
  query,
  onSelect,
}: {
  summary?: { hosts: SlaHostSummary[] };
  targets: SlaTarget[];
  query: string;
  onSelect: (id: number) => void;
}) {
  const hosts = summary?.hosts ?? [];
  const q = query.trim().toLowerCase();
  const filtered = q
    ? hosts.filter((h) => (h.hostname ?? '').toLowerCase().includes(q) || (h.ip_address ?? '').toLowerCase().includes(q))
    : hosts;

  if (filtered.length === 0) {
    return <div className="empty-state">No SLA data available — run monitoring polls to collect metrics.</div>;
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
        const compliance = getHostSlaCompliance(h, targets);
        const uptimeColor = (h.uptime_pct ?? 0) >= 99.9 ? 'success' : (h.uptime_pct ?? 0) >= 99 ? 'warning' : 'danger';
        const badgeColor = compliance.status === 'breach' ? 'danger' : compliance.status === 'warn' ? 'warning' : compliance.status === 'met' ? 'success' : 'text-muted';
        const badgeLabel = compliance.status === 'none' ? 'No Target' : compliance.status === 'met' ? 'Met' : compliance.status === 'warn' ? 'Warning' : 'Breach';
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
              <span style={{ background: `var(--${badgeColor})`, color: 'white', padding: '2px 8px', borderRadius: 3, fontSize: '0.8em', fontWeight: 600 }}>
                {badgeLabel}
              </span>
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

function SlaTargetsTab({ targets }: { targets: SlaTarget[] }) {
  const deleteMut = useDeleteSlaTarget();
  const [editing, setEditing] = useState<SlaTarget | null>(null);
  const [creating, setCreating] = useState(false);

  function handleDelete(t: SlaTarget) {
    if (!confirm(`Delete SLA target '${t.name}'?`)) return;
    deleteMut.mutate(t.id, { onError: (e) => alert((e as Error).message) });
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '0.75rem' }}>
        <button className="btn btn-primary" onClick={() => setCreating(true)}>+ New Target</button>
      </div>
      {targets.length === 0 ? (
        <div className="empty-state">No SLA targets defined</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {targets.map((t) => {
            const scope = t.host_name ? `Host: ${t.host_name}` : t.group_name ? `Group: ${t.group_name}` : 'Global';
            return (
              <div key={t.id} className="card" style={{ padding: '0.75rem 1rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <div>
                    <strong>{t.name}</strong>
                    {!t.enabled && <span className="text-muted" style={{ fontSize: '0.8em', marginLeft: '0.5rem' }}>(disabled)</span>}
                  </div>
                  <div style={{ display: 'flex', gap: '0.4rem' }}>
                    <button className="btn btn-sm btn-secondary" onClick={() => setEditing(t)}>Edit</button>
                    <button className="btn btn-sm btn-danger" onClick={() => handleDelete(t)}>Delete</button>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '1.5rem', marginTop: '0.5rem', fontSize: '0.9em', flexWrap: 'wrap' }}>
                  <div><span className="text-muted">Metric:</span> {METRIC_LABELS[t.metric] ?? t.metric}</div>
                  <div><span className="text-muted">Target:</span> <strong style={{ color: 'var(--success)' }}>{t.target_value}</strong></div>
                  <div><span className="text-muted">Warning:</span> <strong style={{ color: 'var(--warning)' }}>{t.warning_value}</strong></div>
                  <div><span className="text-muted">Scope:</span> {scope}</div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <SlaTargetFormModal
        target={editing}
        isCreate={creating}
        onClose={() => { setEditing(null); setCreating(false); }}
      />
    </div>
  );
}

function SlaTargetFormModal({ target, isCreate, onClose }: { target: SlaTarget | null; isCreate: boolean; onClose: () => void }) {
  const isOpen = isCreate || target != null;
  const createMut = useCreateSlaTarget();
  const updateMut = useUpdateSlaTarget();
  const groups = useInventoryGroupsFull(true);
  const allHosts = useMemo(
    () => (groups.data ?? []).flatMap((g) => (g.hosts ?? []).map((h) => ({ ...h, group_name: g.name }))),
    [groups.data],
  );

  const [name, setName] = useState('');
  const [metric, setMetric] = useState('uptime');
  const [targetValue, setTargetValue] = useState('99.9');
  const [warningValue, setWarningValue] = useState('99.0');
  const [scope, setScope] = useState<'global' | 'group' | 'host'>('global');
  const [groupId, setGroupId] = useState('');
  const [hostId, setHostId] = useState('');

  useEffect(() => {
    if (target) {
      setName(target.name);
      setMetric(target.metric);
      setTargetValue(String(target.target_value));
      setWarningValue(String(target.warning_value));
      if (target.host_id != null) { setScope('host'); setHostId(String(target.host_id)); setGroupId(''); }
      else if (target.group_id != null) { setScope('group'); setGroupId(String(target.group_id)); setHostId(''); }
      else { setScope('global'); setHostId(''); setGroupId(''); }
    } else if (isCreate) {
      setName(''); setMetric('uptime'); setTargetValue('99.9'); setWarningValue('99.0');
      setScope('global'); setGroupId(''); setHostId('');
    }
  }, [target, isCreate]);

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) { alert('Name is required'); return; }
    const data: SlaTargetCreate = {
      name: name.trim(),
      metric,
      target_value: parseFloat(targetValue) || 0,
      warning_value: parseFloat(warningValue) || 0,
      host_id: scope === 'host' ? (Number.isFinite(parseInt(hostId, 10)) ? parseInt(hostId, 10) : null) : null,
      group_id: scope === 'group' ? (Number.isFinite(parseInt(groupId, 10)) ? parseInt(groupId, 10) : null) : null,
    };
    if (target) {
      updateMut.mutate({ id: target.id, data }, {
        onSuccess: onClose,
        onError: (e) => alert((e as Error).message),
      });
    } else {
      createMut.mutate(data, {
        onSuccess: onClose,
        onError: (e) => alert((e as Error).message),
      });
    }
  }

  const pending = createMut.isPending || updateMut.isPending;

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={target ? 'Edit SLA Target' : 'New SLA Target'}>
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label className="form-label">Name</label>
          <input className="form-input" value={name} onChange={(e) => setName(e.target.value)} required />
        </div>
        <div className="form-group">
          <label className="form-label">Metric</label>
          <select className="form-select" value={metric} onChange={(e) => setMetric(e.target.value)}>
            <option value="uptime">Uptime %</option>
            <option value="latency">Latency (ms)</option>
            <option value="jitter">Jitter (ms)</option>
            <option value="packet_loss">Packet Loss %</option>
          </select>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <div className="form-group" style={{ flex: 1 }}>
            <label className="form-label">Target</label>
            <input className="form-input" type="number" step="0.01" value={targetValue} onChange={(e) => setTargetValue(e.target.value)} />
          </div>
          <div className="form-group" style={{ flex: 1 }}>
            <label className="form-label">Warning</label>
            <input className="form-input" type="number" step="0.01" value={warningValue} onChange={(e) => setWarningValue(e.target.value)} />
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">Scope</label>
          <select className="form-select" value={scope} onChange={(e) => setScope(e.target.value as 'global' | 'group' | 'host')}>
            <option value="global">Global (all hosts)</option>
            <option value="group">Group</option>
            <option value="host">Host</option>
          </select>
        </div>
        {scope === 'group' && (
          <div className="form-group">
            <label className="form-label">Group</label>
            <select className="form-select" value={groupId} onChange={(e) => setGroupId(e.target.value)}>
              <option value="">Select group…</option>
              {(groups.data ?? []).map((g) => (
                <option key={g.id} value={g.id}>{g.name}</option>
              ))}
            </select>
          </div>
        )}
        {scope === 'host' && (
          <div className="form-group">
            <label className="form-label">Host</label>
            <select className="form-select" value={hostId} onChange={(e) => setHostId(e.target.value)}>
              <option value="">Select host…</option>
              {allHosts.map((h) => (
                <option key={h.id} value={h.id}>{h.hostname} ({h.group_name})</option>
              ))}
            </select>
          </div>
        )}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={pending}>
            {pending ? 'Saving…' : 'Save'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
