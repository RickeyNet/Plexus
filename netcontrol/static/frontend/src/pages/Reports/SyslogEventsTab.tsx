import { useMemo, useState } from 'react';

import { useSyslogEvents, type SyslogEvent } from '@/api/reports';

import { severityBadgeClass } from './helpers';

const SEVERITIES = [
  { value: '', label: 'All severities' },
  { value: 'emergency', label: 'Emergency' },
  { value: 'alert', label: 'Alert' },
  { value: 'critical', label: 'Critical' },
  { value: 'error', label: 'Error' },
  { value: 'warning', label: 'Warning' },
  { value: 'notice', label: 'Notice' },
  { value: 'info', label: 'Info' },
  { value: 'debug', label: 'Debug' },
];

const TYPES = [
  { value: 'syslog', label: 'Syslog' },
  { value: 'snmp_trap', label: 'SNMP Trap' },
];

export function SyslogEventsTab() {
  const [severity, setSeverity] = useState('');
  const [eventType, setEventType] = useState('syslog');
  const [search, setSearch] = useState('');

  const query = useSyslogEvents({
    severity: severity || undefined,
    eventType,
    limit: 500,
  });

  const data = query.data;
  const items: SyslogEvent[] = useMemo(() => {
    const list = Array.isArray(data) ? data : (data?.events ?? []);
    if (!search) return list;
    const q = search.toLowerCase();
    return list.filter((e) =>
      [e.hostname, e.message, e.event_type, e.severity, e.event_data]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(q)),
    );
  }, [data, search]);

  const total = items.length;
  const critCount = items.filter((e) => ['emergency', 'alert', 'critical'].includes(e.severity || '')).length;
  const errCount = items.filter((e) => e.severity === 'error').length;
  const warnCount = items.filter((e) => e.severity === 'warning').length;

  return (
    <div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '0.75rem', alignItems: 'flex-end' }}>
        <div className="form-group" style={{ marginBottom: 0 }}>
          <label className="form-label">Severity</label>
          <select className="form-select" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            {SEVERITIES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
          </select>
        </div>
        <div className="form-group" style={{ marginBottom: 0 }}>
          <label className="form-label">Type</label>
          <select className="form-select" value={eventType} onChange={(e) => setEventType(e.target.value)}>
            {TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
          </select>
        </div>
        <div className="form-group" style={{ marginBottom: 0, flex: 1, minWidth: 200 }}>
          <label className="form-label">Search</label>
          <input className="form-input" placeholder="Filter…" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '0.75rem', marginBottom: '0.75rem' }}>
        <Card label="Total Events" value={String(total)} />
        <Card label="Critical+" value={String(critCount)} color="var(--danger)" />
        <Card label="Errors" value={String(errCount)} color="var(--danger)" />
        <Card label="Warnings" value={String(warnCount)} color="var(--warning)" />
      </div>

      {query.isPending && <p className="text-muted">Loading…</p>}
      {query.error && <p style={{ color: 'var(--danger)' }}>Failed: {(query.error as Error).message}</p>}
      {query.data && (
        items.length ? (
          <table className="data-table">
            <thead>
              <tr><th>Time</th><th>Host</th><th>Severity</th><th>Type</th><th>Message</th></tr>
            </thead>
            <tbody>
              {items.map((e, i) => (
                <tr key={i}>
                  <td style={{ whiteSpace: 'nowrap' }}>{e.timestamp ? new Date(e.timestamp).toLocaleString() : '-'}</td>
                  <td>{e.hostname || e.host_id || '-'}</td>
                  <td><span className={`badge ${severityBadgeClass(e.severity)}`}>{e.severity || '-'}</span></td>
                  <td>{e.event_type || '-'}</td>
                  <td style={{ maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.message || e.event_data || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <div className="empty-state">No syslog events found.</div>
      )}
    </div>
  );
}

function Card({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div className="card stat-card" style={{ padding: '0.85rem' }}>
      <div className="stat-value" style={color ? { color } : undefined}>{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}
