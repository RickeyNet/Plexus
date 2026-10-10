import { useState } from 'react';

import { Modal } from '@/components/Modal';
import { useMonitoringRouteSnapshots } from '@/api/monitoring';
import { formatTimestamp } from './helpers';

// Route-table history for one host. Opened from a route_churn alert row on
// the Alerts tab (this used to be its own "Route Churn" tab, which was the
// alert list filtered to that metric).
export function RouteSnapshotsModal({ hostId, hostname, onClose }: { hostId: number; hostname: string; onClose: () => void }) {
  const snapshots = useMonitoringRouteSnapshots(hostId, 10);
  const [selected, setSelected] = useState<{ text: string; ts: string } | null>(null);

  return (
    <Modal isOpen onClose={onClose} title={`${hostname} - Route Snapshots`} size="large">
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
        <Modal isOpen onClose={() => setSelected(null)} title={`Route Table - ${selected.ts}`} size="large">
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
