import {
  InterfaceErrorEvent,
  InterfaceErrorSummaryEntry,
  useAcknowledgeErrorEvent,
  useInterfaceErrorEvents,
  useInterfaceErrorSummary,
  useResolveErrorEvent,
} from '@/api/deviceDetail';

import { ErrorChart } from './ErrorChart';

export function ErrorTrendingTab({ hostId }: { hostId: number }) {
  const summary = useInterfaceErrorSummary(hostId);
  const events = useInterfaceErrorEvents(hostId);
  const ack = useAcknowledgeErrorEvent();
  const resolve = useResolveErrorEvent();

  if (summary.isLoading || events.isLoading) {
    return <p className="text-muted">Loading error trending…</p>;
  }
  if (summary.isError && events.isError) {
    return <p className="text-muted">Could not load interface error data</p>;
  }

  const interfaces = summary.data?.interfaces || [];
  const errorEvents = events.data || [];
  const activeEvents = errorEvents.filter((e) => !e.resolved_at);
  const resolvedEvents = errorEvents.filter((e) => e.resolved_at);

  if (!interfaces.length && !errorEvents.length) {
    return (
      <p className="text-muted">
        No interface error data available. Error counters are collected during SNMP polls
        and will appear here after two or more polling cycles.
      </p>
    );
  }

  const withErrors = interfaces
    .filter((iface) => Object.values(iface.metrics || {}).some((d) => (d?.max_value ?? 0) > 0))
    .slice(0, 8);

  return (
    <div>
      {activeEvents.length > 0 && (
        <div
          className="card"
          style={{ borderLeft: '3px solid var(--danger)', marginBottom: '1rem' }}
        >
          <div className="card-body" style={{ padding: '0.75rem' }}>
            <h4 style={{ margin: '0 0 0.5rem', color: 'var(--danger)' }}>
              {activeEvents.length} Active Error Event{activeEvents.length > 1 ? 's' : ''}
            </h4>
            <ActiveEventsTable
              events={activeEvents}
              onAck={(id) => ack.mutate(id)}
              onResolve={(id) => resolve.mutate(id)}
            />
          </div>
        </div>
      )}

      {interfaces.length > 0 && (
        <div className="card" style={{ marginBottom: '1rem' }}>
          <div className="card-body" style={{ padding: '0.75rem' }}>
            <h4 style={{ margin: '0 0 0.5rem' }}>Interface Error Summary (Last 24h)</h4>
            <ErrorSummaryTable interfaces={interfaces} />
          </div>
        </div>
      )}

      {withErrors.length > 0 && (
        <>
          <h4 style={{ margin: '1rem 0 0.5rem' }}>Error Trending Charts</h4>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))',
              gap: '0.75rem',
            }}
          >
            {withErrors.map((iface) => (
              <div key={iface.if_index} className="card" style={{ marginBottom: 0 }}>
                <div
                  className="card-title"
                  style={{ fontSize: '0.85rem', padding: '0.5rem 0.75rem' }}
                >
                  {iface.if_name || `idx-${iface.if_index}`} — Errors
                </div>
                <ErrorChart hostId={hostId} ifIndex={iface.if_index} />
              </div>
            ))}
          </div>
        </>
      )}

      {resolvedEvents.length > 0 && (
        <div className="card" style={{ marginTop: '1rem' }}>
          <div className="card-body" style={{ padding: '0.75rem' }}>
            <h4 style={{ margin: '0 0 0.5rem' }}>Recent Error Events</h4>
            <ResolvedEventsTable events={resolvedEvents.slice(0, 20)} />
          </div>
        </div>
      )}
    </div>
  );
}

function ActiveEventsTable({
  events,
  onAck,
  onResolve,
}: {
  events: InterfaceErrorEvent[];
  onAck: (id: number) => void;
  onResolve: (id: number) => void;
}) {
  return (
    <table className="chart-table" style={{ fontSize: '0.82rem' }}>
      <thead>
        <tr>
          <th>Time</th>
          <th>Interface</th>
          <th>Metric</th>
          <th>Rate</th>
          <th>Severity</th>
          <th>Root Cause</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {events.map((e) => {
          const sevClass = e.severity === 'critical' ? 'danger' : 'warning';
          return (
            <tr key={e.id}>
              <td style={{ whiteSpace: 'nowrap' }}>{new Date(e.created_at).toLocaleString()}</td>
              <td>
                <strong>{e.if_name || `idx-${e.if_index}`}</strong>
              </td>
              <td>{e.metric_name}</td>
              <td>
                {e.current_rate != null ? `${e.current_rate.toFixed(2)}/s` : '-'}{' '}
                <span className="text-muted">
                  ({e.spike_factor != null ? e.spike_factor.toFixed(1) : '?'}× baseline)
                </span>
              </td>
              <td>
                <span className={`badge badge-${sevClass}`}>{e.severity}</span>
              </td>
              <td style={{ maxWidth: 300 }}>
                {e.root_cause_hint || e.root_cause_category || 'unknown'}
              </td>
              <td>
                <button
                  className="btn btn-sm btn-secondary"
                  style={{ padding: '2px 6px', fontSize: '0.75em' }}
                  onClick={() => onAck(e.id)}
                >
                  {e.acknowledged ? 'Acked' : 'Ack'}
                </button>{' '}
                <button
                  className="btn btn-sm btn-secondary"
                  style={{ padding: '2px 6px', fontSize: '0.75em' }}
                  onClick={() => onResolve(e.id)}
                >
                  Resolve
                </button>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function ErrorSummaryTable({
  interfaces,
}: {
  interfaces: InterfaceErrorSummaryEntry[];
}) {
  const fmtMetric = (entry: InterfaceErrorSummaryEntry, key: string) => {
    const d = entry.metrics?.[key];
    if (!d || d.max_value == null) return <span className="text-muted">0</span>;
    const val = d.max_value;
    const color = val > 100 ? 'var(--danger)' : val > 0 ? 'var(--warning)' : 'var(--text-secondary)';
    return (
      <span style={{ color, fontWeight: val > 0 ? 600 : 400 }}>{val.toLocaleString()}</span>
    );
  };
  return (
    <table className="chart-table" style={{ fontSize: '0.82rem' }}>
      <thead>
        <tr>
          <th>Interface</th>
          <th>In Errors</th>
          <th>Out Errors</th>
          <th>In Discards</th>
          <th>Out Discards</th>
        </tr>
      </thead>
      <tbody>
        {interfaces.map((iface) => (
          <tr key={iface.if_index}>
            <td>
              <strong>{iface.if_name || `idx-${iface.if_index}`}</strong>
            </td>
            <td>{fmtMetric(iface, 'if_in_errors')}</td>
            <td>{fmtMetric(iface, 'if_out_errors')}</td>
            <td>{fmtMetric(iface, 'if_in_discards')}</td>
            <td>{fmtMetric(iface, 'if_out_discards')}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ResolvedEventsTable({ events }: { events: InterfaceErrorEvent[] }) {
  return (
    <table className="chart-table" style={{ fontSize: '0.82rem' }}>
      <thead>
        <tr>
          <th>Time</th>
          <th>Interface</th>
          <th>Metric</th>
          <th>Category</th>
          <th>Hint</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {events.map((e) => (
          <tr key={e.id}>
            <td style={{ whiteSpace: 'nowrap' }}>{new Date(e.created_at).toLocaleString()}</td>
            <td>{e.if_name}</td>
            <td>{e.metric_name}</td>
            <td>
              <span className="badge badge-secondary">{e.root_cause_category || 'unknown'}</span>
            </td>
            <td style={{ maxWidth: 300 }}>{e.root_cause_hint || ''}</td>
            <td>Resolved</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

