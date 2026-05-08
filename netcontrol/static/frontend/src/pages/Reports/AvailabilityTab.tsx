import { useState } from 'react';

import { useInventoryGroups } from '@/api/compliance';
import {
  useAvailabilityOutages,
  useAvailabilitySummary,
  useAvailabilityTransitions,
  type AvailabilityHostSummary,
  type AvailabilityOutage,
  type AvailabilityTransition,
} from '@/api/reports';

import { availabilityBadgeClass, formatDuration } from './helpers';

type AvailTab = 'hosts' | 'outages' | 'transitions';

const PERIODS = [
  { value: 1, label: 'Last 1 day' },
  { value: 7, label: 'Last 7 days' },
  { value: 30, label: 'Last 30 days' },
  { value: 90, label: 'Last 90 days' },
];

export function AvailabilityTab() {
  const groupsQuery = useInventoryGroups(false);
  const [groupId, setGroupId] = useState('');
  const [days, setDays] = useState(7);
  const [tab, setTab] = useState<AvailTab>('hosts');

  const summaryQuery = useAvailabilitySummary(groupId || null, days);
  const outagesQuery = useAvailabilityOutages(groupId || null, days);
  const transitionsQuery = useAvailabilityTransitions();

  const hosts: AvailabilityHostSummary[] = summaryQuery.data?.hosts ?? [];
  const outagesData = outagesQuery.data;
  const outages: AvailabilityOutage[] = Array.isArray(outagesData) ? outagesData : (outagesData?.outages ?? []);
  const transitionsData = transitionsQuery.data;
  const transitions: AvailabilityTransition[] = Array.isArray(transitionsData) ? transitionsData : (transitionsData?.transitions ?? []);

  const upHosts = hosts.filter((h) => h.current_state === 'up').length;
  const totalHosts = hosts.length;
  const avgUptime = totalHosts > 0
    ? hosts.reduce((s, h) => s + (h.uptime_pct ?? 0), 0) / totalHosts
    : 0;

  return (
    <div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '0.75rem' }}>
        <div className="form-group" style={{ marginBottom: 0 }}>
          <label className="form-label">Group</label>
          <select className="form-select" value={groupId} onChange={(e) => setGroupId(e.target.value)}>
            <option value="">All Groups</option>
            {(groupsQuery.data ?? []).map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
          </select>
        </div>
        <div className="form-group" style={{ marginBottom: 0 }}>
          <label className="form-label">Period</label>
          <select className="form-select" value={days} onChange={(e) => setDays(parseInt(e.target.value, 10))}>
            {PERIODS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
          </select>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem', marginBottom: '0.75rem' }}>
        <SummaryCard label="Hosts Up" value={`${upHosts}/${totalHosts}`} />
        <SummaryCard label="Avg Uptime" value={`${avgUptime.toFixed(2)}%`} />
        <SummaryCard label={`Outages (${days}d)`} value={String(outages.length)} />
        <SummaryCard label="Transitions" value={String(transitions.length)} />
      </div>

      <div className="tab-controls">
        {(['hosts', 'outages', 'transitions'] as AvailTab[]).map((t) => (
          <button
            key={t}
            type="button"
            className={`btn btn-sm btn-secondary upgrade-tab-btn${tab === t ? ' active' : ''}`}
            onClick={() => setTab(t)}
          >
            {t === 'hosts' ? 'Hosts' : t === 'outages' ? 'Outages' : 'Transitions'}
          </button>
        ))}
      </div>

      {tab === 'hosts' && <HostsList hosts={hosts} />}
      {tab === 'outages' && <OutagesList outages={outages} />}
      {tab === 'transitions' && <TransitionsList transitions={transitions} />}
    </div>
  );
}

function SummaryCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="card stat-card" style={{ padding: '0.85rem' }}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

function HostsList({ hosts }: { hosts: AvailabilityHostSummary[] }) {
  if (!hosts.length) {
    return <div className="empty-state">No availability data yet. Enable monitoring to start tracking.</div>;
  }
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Host</th>
          <th>State</th>
          <th>Uptime %</th>
          <th>Total Up</th>
          <th>Total Down</th>
          <th>Transitions</th>
        </tr>
      </thead>
      <tbody>
        {hosts.map((h) => (
          <tr key={h.host_id}>
            <td>{h.hostname || `Host #${h.host_id}`}</td>
            <td><span className={`badge ${availabilityBadgeClass(h.current_state)}`}>{h.current_state || 'unknown'}</span></td>
            <td>{h.uptime_pct != null ? h.uptime_pct.toFixed(2) + '%' : 'N/A'}</td>
            <td>{h.total_up_seconds != null ? formatDuration(h.total_up_seconds) : '-'}</td>
            <td>{h.total_down_seconds != null ? formatDuration(h.total_down_seconds) : '-'}</td>
            <td>{h.transition_count ?? '-'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function OutagesList({ outages }: { outages: AvailabilityOutage[] }) {
  if (!outages.length) return <div className="empty-state">No outages recorded.</div>;
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Host</th>
          <th>Started</th>
          <th>Ended</th>
          <th>Duration</th>
        </tr>
      </thead>
      <tbody>
        {outages.map((o, i) => (
          <tr key={i}>
            <td>{o.hostname || `Host #${o.host_id}`}</td>
            <td>{o.down_at ? new Date(o.down_at).toLocaleString() : '-'}</td>
            <td>{o.up_at ? new Date(o.up_at).toLocaleString() : 'Ongoing'}</td>
            <td>{o.duration_seconds != null ? formatDuration(o.duration_seconds) : 'Ongoing'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function TransitionsList({ transitions }: { transitions: AvailabilityTransition[] }) {
  if (!transitions.length) return <div className="empty-state">No state transitions recorded.</div>;
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Host</th>
          <th>Entity</th>
          <th>From</th>
          <th>To</th>
          <th>Time</th>
        </tr>
      </thead>
      <tbody>
        {transitions.map((t, i) => (
          <tr key={i}>
            <td>{t.hostname || `Host #${t.host_id}`}</td>
            <td>{(t.entity_type ?? '') + (t.entity_id ? ' ' + t.entity_id : '')}</td>
            <td><span className={`badge ${availabilityBadgeClass(t.old_state)}`}>{t.old_state}</span></td>
            <td><span className={`badge ${availabilityBadgeClass(t.new_state)}`}>{t.new_state}</span></td>
            <td>{t.transition_at ? new Date(t.transition_at).toLocaleString() : '-'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
