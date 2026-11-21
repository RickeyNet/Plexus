import { useId, useState } from 'react';

import { useSecurityEvents } from '@/api/securityEvents';
import { Badge, SeverityBadge } from '@/components/Badge';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { StatGrid, StatTile } from '@/components/StatTile';
import { formatBackendTimestamp } from '@/lib/datetime';
import { useDebouncedValue } from '@/lib/useDebouncedValue';

import { countTone } from './helpers';
import {
  actionBadge,
  addressPort,
  eventDevice,
  pageLabel,
  SECURITY_ACTIONS,
  SECURITY_PAGE_SIZE,
  SECURITY_SEVERITIES,
  SECURITY_WINDOWS,
} from './securityEvents';

/**
 * Security events: the intrusion detection (Suricata) alerts of OPNsense
 * firewalls, read by each collection of the source and, for a firewall that
 * is an inventory host, by every monitoring poll. Alerting happens on the
 * server (one alert per firewall and signature, see the Alerts tab); this
 * list is read-only.
 */
export function SecurityTab() {
  const fid = useId();
  const [hours, setHours] = useState(24);
  const [severity, setSeverity] = useState('');
  const [action, setAction] = useState('');
  const [search, setSearch] = useState('');
  const [offset, setOffset] = useState(0);
  const q = useDebouncedValue(search.trim());

  const query = useSecurityEvents({ hours, severity, action, q, limit: SECURITY_PAGE_SIZE, offset });
  const data = query.data;
  const events = data?.events ?? [];
  const counts = data?.counts;
  const filtered = !!severity || !!action || !!q;

  function changeFilter(apply: () => void) {
    apply();
    setOffset(0);
  }

  return (
    <div>
      <p className="text-muted" style={{ marginTop: 0, fontSize: '0.85em' }}>
        Intrusion detection alerts of OPNsense firewalls (Suricata), read over the API with the source&apos;s
        collection and every monitoring poll of a firewall that is an inventory host. Priority 1 and 2 signatures
        raise one alert per firewall and signature; it resolves after an hour without a new event.
      </p>
      <div className="toolbar" style={{ alignItems: 'flex-end', flexWrap: 'wrap' }}>
        <div className="form-group" style={{ marginBottom: 0 }}>
          <label className="form-label" htmlFor={`${fid}-window`}>Window</label>
          <select
            id={`${fid}-window`}
            className="form-select"
            value={hours}
            onChange={(e) => changeFilter(() => setHours(Number(e.target.value)))}
          >
            {SECURITY_WINDOWS.map((w) => <option key={w.hours} value={w.hours}>{w.label}</option>)}
          </select>
        </div>
        <div className="form-group" style={{ marginBottom: 0 }}>
          <label className="form-label" htmlFor={`${fid}-severity`}>Severity</label>
          <select
            id={`${fid}-severity`}
            className="form-select"
            value={severity}
            onChange={(e) => changeFilter(() => setSeverity(e.target.value))}
          >
            {SECURITY_SEVERITIES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
          </select>
        </div>
        <div className="form-group" style={{ marginBottom: 0 }}>
          <label className="form-label" htmlFor={`${fid}-action`}>Action</label>
          <select
            id={`${fid}-action`}
            className="form-select"
            value={action}
            onChange={(e) => changeFilter(() => setAction(e.target.value))}
          >
            {SECURITY_ACTIONS.map((a) => <option key={a.value} value={a.value}>{a.label}</option>)}
          </select>
        </div>
        <div className="form-group" style={{ marginBottom: 0, flex: 1, minWidth: 200 }}>
          <label className="form-label" htmlFor={`${fid}-search`}>Search</label>
          <input
            id={`${fid}-search`}
            className="form-input"
            placeholder="Signature, sid, category or address"
            maxLength={200}
            value={search}
            onChange={(e) => changeFilter(() => setSearch(e.target.value))}
          />
        </div>
      </div>

      <StatGrid compact>
        <StatTile label="Events" value={String(data?.total ?? '-')} />
        <StatTile label="Critical" value={String(counts?.critical ?? '-')} tone={countTone(counts?.critical, 'danger')} />
        <StatTile label="Warning" value={String(counts?.warning ?? '-')} tone={countTone(counts?.warning, 'warning')} />
        <StatTile label="Info / unknown" value={counts ? String(counts.info + counts.unknown) : '-'} />
        <StatTile label="Blocked" value={String(counts?.blocked ?? '-')} />
      </StatGrid>

      {query.error && !data ? (
        <QueryError what="security events" query={query} />
      ) : query.isPending ? (
        <LoadingState />
      ) : !events.length ? (
        <EmptyState
          message="No security events in this window."
          description={
            filtered
              ? 'No event matches the filters.'
              : 'Turn on the IDS of an OPNsense firewall and the "IDS alerts" option of its topology source.'
          }
        />
      ) : (
        <>
          <DataTable stickyHeader maxHeight={620} aria-label="Security events">
            <thead>
              <tr>
                <th>Time</th>
                <th>Severity</th>
                <th>Action</th>
                <th>Signature</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Protocol</th>
                <th>Device</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => {
                const done = actionBadge(e.action);
                return (
                  <tr key={e.id}>
                    <td style={{ whiteSpace: 'nowrap' }}>{formatBackendTimestamp(e.occurred_at)}</td>
                    <td><SeverityBadge severity={e.severity} /></td>
                    <td><Badge tone={done.tone} size="sm">{done.text}</Badge></td>
                    <td style={{ minWidth: 240 }}>
                      {e.signature || '-'}
                      <div className="text-muted" style={{ fontSize: '0.85em' }}>
                        sid {e.signature_id ?? '-'}
                        {e.category ? ` · ${e.category}` : ''}
                        {e.priority != null ? ` · priority ${e.priority}` : ''}
                      </div>
                    </td>
                    <td style={{ whiteSpace: 'nowrap' }}>{addressPort(e.src_ip, e.src_port)}</td>
                    <td style={{ whiteSpace: 'nowrap' }}>{addressPort(e.dest_ip, e.dest_port)}</td>
                    <td>
                      {e.protocol || '-'}
                      {e.app_proto && e.app_proto !== 'failed' ? ` / ${e.app_proto}` : ''}
                    </td>
                    <td>
                      {eventDevice(e)}
                      {e.interface && <div className="text-muted" style={{ fontSize: '0.85em' }}>{e.interface}</div>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </DataTable>
          <div className="toolbar" style={{ justifyContent: 'space-between', marginTop: 'var(--space-2)' }}>
            <span className="text-muted">{pageLabel(offset, events.length, data?.total ?? 0)}</span>
            <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - SECURITY_PAGE_SIZE))}
              >
                Show newer
              </button>
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                disabled={offset + events.length >= (data?.total ?? 0)}
                onClick={() => setOffset(offset + SECURITY_PAGE_SIZE)}
              >
                Show older
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
