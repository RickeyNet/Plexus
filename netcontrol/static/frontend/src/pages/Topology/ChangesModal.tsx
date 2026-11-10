import { useEffect, useState } from 'react';

import {
  fetchTopologyChanges,
  useAcknowledgeTopologyChanges,
  type TopologyChange,
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

const PROTO_LABEL: Record<string, string> = {
  cdp: 'CDP',
  lldp: 'LLDP',
  ospf: 'OSPF',
  bgp: 'BGP',
  'inferred-fdb': 'INFERRED',
};

export function ChangesModal({ isOpen, onClose, onAcknowledged }: Props) {
  const [changes, setChanges] = useState<TopologyChange[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<Error | null>(null);
  const [ackError, setAckError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const { confirm } = useDialogs();
  const ack = useAcknowledgeTopologyChanges();

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
    fetchTopologyChanges(true, 200)
      .then((r) => {
        if (cancelled) return;
        setChanges(r.changes ?? []);
      })
      .catch((e: Error) => {
        if (!cancelled) setLoadError(e);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [isOpen, reloadKey]);

  async function handleAck() {
    const count = changes.length >= 200 ? `${changes.length} or more` : String(changes.length);
    const ok = await confirm({
      title: 'Acknowledge topology changes',
      message: `Acknowledge all ${count} unacknowledged topology change${changes.length === 1 ? '' : 's'}?`,
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
    <Modal isOpen={isOpen} onClose={onClose} title="Topology Changes">
      {loading && <LoadingState />}
      {loadError && <QueryError what="topology changes" error={loadError} onRetry={reload} />}
      {ackError && <Callout tone="danger">Failed to acknowledge: {ackError}</Callout>}
      {!loading && !loadError && !changes.length && (
        <EmptyState compact message="No topology changes recorded." />
      )}
      {!loading && !loadError && changes.length > 0 && (
        <>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <span className="text-muted" style={{ fontSize: '0.85rem' }}>
              {changes.length} change{changes.length !== 1 ? 's' : ''} detected
            </span>
            <BusyButton className="btn btn-secondary btn-sm" busy={ack.isPending} busyLabel="Acknowledging…" onClick={() => void handleAck()}>
              Acknowledge All
            </BusyButton>
          </div>
          <div style={{ maxHeight: '420px', overflowY: 'auto' }}>
            {changes.map((c, i) => {
              const isAdded = c.change_type === 'added';
              const color = isAdded ? 'var(--success)' : 'var(--danger)';
              const proto = PROTO_LABEL[c.protocol ?? ''] ?? (c.protocol ?? '').toUpperCase();
              return (
                <div
                  key={i}
                  style={{
                    background: `${color}14`,
                    borderLeft: `3px solid ${color}`,
                    padding: '0.5rem 0.75rem',
                    marginBottom: '0.4rem',
                    borderRadius: '0.25rem',
                    opacity: c.acknowledged ? 0.5 : 1,
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ fontWeight: 600, color, fontSize: '0.9rem' }}>
                      {isAdded ? '+' : '−'} {c.change_type.toUpperCase()}
                    </span>
                    <span className="text-muted" style={{ fontSize: '0.7rem' }}>
                      {formatBackendDateTime(c.detected_at)}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.82rem', marginTop: '0.2rem' }}>
                    <strong>{c.source_hostname || `Host #${c.source_host_id}`}</strong>
                    {c.source_interface ? ` (${c.source_interface})` : ''}
                    {' ↔ '}
                    <strong>{c.target_device_name || c.target_ip || 'unknown'}</strong>
                    {c.target_interface ? ` (${c.target_interface})` : ''}
                    {proto && (
                      <span style={{
                        marginLeft: '0.4rem',
                        fontSize: '0.7rem',
                        padding: '0.1rem 0.35rem',
                        background: 'rgba(from var(--text) r g b / 0.07)',
                        borderRadius: '0.2rem',
                      }}>{proto}</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </>
      )}
    </Modal>
  );
}
