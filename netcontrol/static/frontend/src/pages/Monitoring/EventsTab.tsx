import { useMemo, useState } from 'react';

import { useSyslogEvents, type SyslogEvent } from '@/api/monitoring';
import { SeverityBadge } from '@/components/Badge';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { StatGrid, StatTile } from '@/components/StatTile';
import { formatBackendTimestamp } from '@/lib/datetime';

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

export function EventsTab() {
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
      <div className="toolbar" style={{ alignItems: 'flex-end' }}>
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

      <StatGrid compact>
        <StatTile label="Total Events" value={String(total)} />
        <StatTile label="Critical+" value={String(critCount)} tone="danger" />
        <StatTile label="Errors" value={String(errCount)} tone="danger" />
        <StatTile label="Warnings" value={String(warnCount)} tone="warning" />
      </StatGrid>

      {query.error && !query.data ? (
        <QueryError what="events" query={query} />
      ) : (
        query.isPending && <LoadingState />
      )}
      {query.data && (
        items.length ? (
          <table className="data-table">
            <thead>
              <tr><th>Time</th><th>Host</th><th>Severity</th><th>Type</th><th>Message</th></tr>
            </thead>
            <tbody>
              {items.map((e, i) => (
                <tr key={i}>
                  <td style={{ whiteSpace: 'nowrap' }}>{formatBackendTimestamp(e.received_at)}</td>
                  <td>{e.hostname || e.host_id || '-'}</td>
                  <td><SeverityBadge severity={e.severity} /></td>
                  <td>{e.event_type || '-'}</td>
                  <td style={{ maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.message || e.event_data || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <EmptyState message="No syslog events found." />
      )}
    </div>
  );
}

