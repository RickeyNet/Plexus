import { useEffect, useState } from 'react';

import {
  fetchTopologyStpEvents,
  useAcknowledgeStpEvents,
  type StpEvent,
} from '@/api/topology';
import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import { formatBackendDateTime } from '@/lib/datetime';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onAcknowledged: () => void;
}

export function StpEventsModal({ isOpen, onClose, onAcknowledged }: Props) {
  const [events, setEvents] = useState<StpEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<Error | null>(null);
  const [ackError, setAckError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const { confirm } = useDialogs();
  const ack = useAcknowledgeStpEvents();

  const [prevOpen, setPrevOpen] = useState(isOpen);
  if (isOpen !== prevOpen) {
    setPrevOpen(isOpen);
    if (isOpen) {
      setLoading(true);
      setLoadError(null);
      setAckError(null);
    }
  }

  function reload() {
    setLoading(true);
    setLoadError(null);
    setReloadKey((k) => k + 1);
  }

  useEffect(() => {
    if (!isOpen) return;
    let cancelled = false;
    fetchTopologyStpEvents(true, 300)
      .then((r) => { if (!cancelled) setEvents(r.events ?? []); })
      .catch((e: Error) => { if (!cancelled) setLoadError(e); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [isOpen, reloadKey]);

  async function handleAck() {
    const count = events.length >= 300 ? `${events.length} or more` : String(events.length);
    const ok = await confirm({
      title: 'Acknowledge STP events',
      message: `Acknowledge all ${count} unacknowledged STP event${events.length === 1 ? '' : 's'}?`,
      confirmLabel: 'Acknowledge all',
      confirmVariant: 'primary',
    });
    if (!ok) return;
    setAckError(null);
    try {
      await ack.mutateAsync();
      onAcknowledged();
      onClose();
    } catch (e) {
      setAckError((e as Error).message);
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="STP Topology Events">
      {loading && <LoadingState />}
      {loadError && <QueryError what="STP events" error={loadError} onRetry={reload} />}
      {ackError && <Callout tone="danger">Failed to acknowledge: {ackError}</Callout>}
      {!loading && !loadError && !events.length && <EmptyState compact message="No unacknowledged STP events." />}
      {!loading && !loadError && events.length > 0 && (
        <>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <span className="text-muted" style={{ fontSize: '0.85rem' }}>
              {events.length} unacknowledged event{events.length !== 1 ? 's' : ''}
            </span>
            <BusyButton className="btn btn-secondary btn-sm" busy={ack.isPending} busyLabel="Acknowledging…" onClick={() => void handleAck()}>
              Acknowledge All
            </BusyButton>
          </div>
          <div style={{ maxHeight: '420px', overflowY: 'auto' }}>
            {events.map((ev, i) => {
              const sev = String(ev.severity ?? 'warning').toLowerCase();
              const sevColor = sev === 'critical' ? 'var(--danger)' : 'var(--warning)';
              return (
                <div
                  key={i}
                  style={{
                    padding: '0.55rem 0.7rem',
                    marginBottom: '0.45rem',
                    borderRadius: '0.35rem',
                    borderLeft: `3px solid ${sevColor}`,
                    background: `color-mix(in srgb, ${sevColor} 8%, transparent)`,
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.75rem' }}>
                    <strong style={{ fontSize: '0.86rem', color: sevColor }}>
                      {(ev.event_type ?? 'event').replaceAll('_', ' ').toUpperCase()}
                    </strong>
                    <span className="text-muted" style={{ fontSize: '0.72rem' }}>
                      {formatBackendDateTime(ev.created_at)}
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
