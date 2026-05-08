import { useState } from 'react';

import { Modal } from '@/components/Modal';
import { useMonitoringAlerts, useMonitoringPolls, useMonitoringRouteSnapshots } from '@/api/monitoring';
import { formatTimestamp } from './helpers';

export function RoutesTab() {
  const polls = useMonitoringPolls();
  const alerts = useMonitoringAlerts({ limit: 200 });
  const [historyHost, setHistoryHost] = useState<{ id: number; hostname: string } | null>(null);

  const routeAlerts = (alerts.data ?? []).filter((a) => a.metric === 'route_churn');
  const pollsWithRoutes = (polls.data ?? []).filter((p) => p.route_count > 0);

  return (
    <div>
      {!routeAlerts.length ? (
        <div className="card" style={{ padding: '1rem' }}>
          <p className="text-muted">No route churn events detected. Routes are stable across {pollsWithRoutes.length} monitored device(s).</p>
          <p className="text-muted" style={{ fontSize: '0.85em' }}>Route churn alerts are generated when the route table changes between polling cycles.</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {routeAlerts.map((a) => (
            <div key={a.id} className="card" style={{ padding: '0.75rem 1rem', borderLeft: '3px solid var(--warning)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <strong>{a.hostname}</strong>
                  <span className="text-muted" style={{ marginLeft: '0.5rem', fontSize: '0.85em' }}>{a.ip_address}</span>
                </div>
                <button
                  className="btn btn-sm btn-secondary"
                  onClick={() => setHistoryHost({ id: a.host_id, hostname: a.hostname ?? '' })}
                >
                  View History
                </button>
              </div>
              <div style={{ marginTop: '0.3rem', fontSize: '0.9em' }}>{a.message}</div>
              <div className="text-muted" style={{ marginTop: '0.2rem', fontSize: '0.8em' }}>{formatTimestamp(a.created_at)}</div>
            </div>
          ))}
        </div>
      )}

      {historyHost && (
        <RouteSnapshotsModal
          hostId={historyHost.id}
          hostname={historyHost.hostname}
          onClose={() => setHistoryHost(null)}
        />
      )}
    </div>
  );
}

function RouteSnapshotsModal({ hostId, hostname, onClose }: { hostId: number; hostname: string; onClose: () => void }) {
  const snapshots = useMonitoringRouteSnapshots(hostId, 10);
  const [selected, setSelected] = useState<{ text: string; ts: string } | null>(null);

  return (
    <Modal isOpen onClose={onClose} title={`${hostname} — Route Snapshots`} size="large">
      {snapshots.isPending && <div className="text-muted">Loading…</div>}
      {snapshots.error && <div style={{ color: 'var(--danger)' }}>Error: {(snapshots.error as Error).message}</div>}
      {snapshots.data && (snapshots.data.length === 0 ? (
        <div className="empty-state">No route snapshots available</div>
      ) : (
        <div style={{ maxHeight: 400, overflow: 'auto', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
          {snapshots.data.map((s, i) => {
            const prev = snapshots.data?.[i + 1];
            const delta = prev ? s.route_count - prev.route_count : 0;
            return (
              <div key={s.id} className="card" style={{ padding: '0.5rem 0.75rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <span className="text-muted" style={{ fontSize: '0.85em' }}>{formatTimestamp(s.captured_at)}</span>
                    <span style={{ marginLeft: '0.75rem' }}>Routes: <strong>{s.route_count}</strong></span>
                    <span style={{ marginLeft: '0.5rem', fontSize: '0.85em' }}>
                      Delta:{' '}
                      <span style={{ color: delta > 0 ? 'var(--success)' : delta < 0 ? 'var(--danger)' : 'var(--text-muted)' }}>
                        {delta > 0 ? `+${delta}` : delta}
                      </span>
                    </span>
                  </div>
                  <button
                    className="btn btn-sm btn-secondary"
                    onClick={() => setSelected({ text: s.routes_text ?? '', ts: formatTimestamp(s.captured_at) })}
                  >
                    View
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      ))}

      {selected && (
        <Modal isOpen onClose={() => setSelected(null)} title={`Route Table — ${selected.ts}`} size="large">
          <pre style={{ background: 'var(--bg-secondary)', padding: '0.75rem', borderRadius: 4, maxHeight: 400, overflow: 'auto', fontSize: '0.8em' }}>
            {selected.text || '(empty)'}
          </pre>
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
            <button
              className="btn btn-sm btn-secondary"
              onClick={() => navigator.clipboard.writeText(selected.text)}
            >
              Copy
            </button>
          </div>
        </Modal>
      )}
    </Modal>
  );
}
