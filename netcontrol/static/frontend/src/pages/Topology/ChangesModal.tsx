import { useEffect, useState } from 'react';

import {
  fetchTopologyChanges,
  useAcknowledgeTopologyChanges,
  type TopologyChange,
} from '@/api/topology';
import { Modal } from '@/components/Modal';

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
  const [error, setError] = useState<string | null>(null);
  const ack = useAcknowledgeTopologyChanges();

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
    fetchTopologyChanges(true, 200)
      .then((r) => {
        if (cancelled) return;
        setChanges(r.changes ?? []);
      })
      .catch((e: Error) => {
        if (!cancelled) setError(e.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
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
    <Modal isOpen={isOpen} onClose={onClose} title="Topology Changes" size="large">
      {loading && <div className="text-muted">Loading…</div>}
      {error && <div style={{ color: 'var(--danger)' }}>Error: {error}</div>}
      {!loading && !changes.length && (
        <p className="text-muted">No topology changes recorded.</p>
      )}
      {!loading && changes.length > 0 && (
        <>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <span className="text-muted" style={{ fontSize: '0.85rem' }}>
              {changes.length} change{changes.length !== 1 ? 's' : ''} detected
            </span>
            <button className="btn btn-secondary btn-sm" onClick={handleAck} disabled={ack.isPending}>
              {ack.isPending ? 'Acknowledging…' : 'Acknowledge All'}
            </button>
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
                      {new Date((c.detected_at || '') + 'Z').toLocaleString()}
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
                        background: 'rgba(255,255,255,0.07)',
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
