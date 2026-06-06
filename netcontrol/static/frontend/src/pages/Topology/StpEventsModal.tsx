import { useEffect, useState } from 'react';

import {
  fetchTopologyStpEvents,
  useAcknowledgeStpEvents,
  type StpEvent,
} from '@/api/topology';
import { Modal } from '@/components/Modal';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onAcknowledged: () => void;
}

export function StpEventsModal({ isOpen, onClose, onAcknowledged }: Props) {
  const [events, setEvents] = useState<StpEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ack = useAcknowledgeStpEvents();

  const [prevOpen, setPrevOpen] = useState(isOpen);
  if (isOpen !== prevOpen) {
    setPrevOpen(isOpen);
    if (isOpen) {
      setLoading(true);
      setError(null);
    }
  }

  useEffect(() => {
    if (!isOpen) return;
    let cancelled = false;
    fetchTopologyStpEvents(true, 300)
      .then((r) => { if (!cancelled) setEvents(r.events ?? []); })
      .catch((e: Error) => { if (!cancelled) setError(e.message); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [isOpen]);

  async function handleAck() {
    try {
      await ack.mutateAsync();
      onAcknowledged();
      onClose();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="STP Topology Events" size="large">
      {loading && <div className="text-muted">Loading…</div>}
      {error && <div style={{ color: 'var(--danger)' }}>Error: {error}</div>}
      {!loading && !events.length && <p className="text-muted">No unacknowledged STP events.</p>}
      {!loading && events.length > 0 && (
        <>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <span className="text-muted" style={{ fontSize: '0.85rem' }}>
              {events.length} unacknowledged event{events.length !== 1 ? 's' : ''}
            </span>
            <button className="btn btn-secondary btn-sm" onClick={handleAck} disabled={ack.isPending}>
              {ack.isPending ? 'Acknowledging…' : 'Acknowledge All'}
            </button>
          </div>
          <div style={{ maxHeight: '420px', overflowY: 'auto' }}>
            {events.map((ev, i) => {
              const sev = String(ev.severity ?? 'warning').toLowerCase();
              const sevColor = sev === 'critical' ? '#ef5350' : '#ffb300';
              return (
                <div
                  key={i}
                  style={{
                    padding: '0.55rem 0.7rem',
                    marginBottom: '0.45rem',
                    borderRadius: '0.35rem',
                    borderLeft: `3px solid ${sevColor}`,
                    background: `${sevColor}14`,
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.75rem' }}>
                    <strong style={{ fontSize: '0.86rem', color: sevColor }}>
                      {(ev.event_type ?? 'event').replaceAll('_', ' ').toUpperCase()}
                    </strong>
                    <span className="text-muted" style={{ fontSize: '0.72rem' }}>
                      {new Date((ev.created_at || '') + 'Z').toLocaleString()}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.8rem', marginTop: '0.2rem' }}>
                    <strong>{ev.hostname || `Host #${ev.host_id}`}</strong>
                    {' · VLAN '}{ev.vlan_id ?? ''}{' · '}
                    {ev.interface_name ? <span style={{ opacity: 0.85 }}>{ev.interface_name}</span> : <span style={{ opacity: 0.7 }}>host-level</span>}
                  </div>
                  {(ev.details || ev.event_type) && (
                    <div style={{ fontSize: '0.8rem', marginTop: '0.2rem' }}>
                      {ev.details || ev.event_type}
                    </div>
                  )}
                  {(ev.old_value || ev.new_value) && (
                    <div style={{ fontFamily: 'monospace', fontSize: '0.75rem', marginTop: '0.25rem', color: 'var(--text-muted)' }}>
                      {ev.old_value || ''} → {ev.new_value || ''}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </>
      )}
    </Modal>
  );
}
