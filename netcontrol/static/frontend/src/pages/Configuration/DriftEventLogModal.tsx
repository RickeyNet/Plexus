import {
  useConfigDriftEvent,
  useConfigDriftEventHistory,
} from '@/api/configuration';
import { Modal } from '@/components/Modal';

import { formatStamp } from './helpers';

interface Props {
  eventId: number | null;
  onClose: () => void;
}

export function DriftEventLogModal({ eventId, onClose }: Props) {
  const ev = useConfigDriftEvent(eventId);
  const history = useConfigDriftEventHistory(eventId, 500);

  const isPending = ev.isPending || history.isPending;
  const title = ev.data
    ? `Drift Event Log — ${ev.data.hostname || ev.data.ip_address || ''}`
    : 'Drift Event Log';
  const entries = history.data || [];

  return (
    <Modal isOpen={eventId != null} onClose={onClose} title={title} size="large">
      {isPending && <p className="text-muted">Loading…</p>}
      {ev.data && (
        <>
          <div
            style={{
              marginBottom: '0.75rem',
              display: 'flex',
              gap: '0.5rem',
              flexWrap: 'wrap',
              fontSize: '0.85rem',
            }}
          >
            <span>Event ID: {ev.data.id}</span>
            <span style={{ opacity: 0.4 }}>|</span>
            <span>Status: {ev.data.status}</span>
            <span style={{ opacity: 0.4 }}>|</span>
            <span>Detected: {formatStamp(ev.data.detected_at)}</span>
          </div>
          <div style={{ maxHeight: '60vh', overflow: 'auto' }}>
            {entries.length === 0 ? (
              <div
                className="card"
                style={{
                  textAlign: 'center',
                  color: 'var(--text-muted)',
                  padding: '1rem',
                }}
              >
                No history entries recorded yet.
              </div>
            ) : (
              entries.map((item, i) => (
                <div
                  key={i}
                  className="card"
                  style={{ marginBottom: '0.5rem', padding: '0.75rem' }}
                >
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      gap: '0.5rem',
                      flexWrap: 'wrap',
                    }}
                  >
                    <strong>{item.action}</strong>
                    <span
                      style={{
                        fontSize: '0.85em',
                        color: 'var(--text-muted)',
                      }}
                    >
                      {formatStamp(item.created_at) || '-'}
                    </span>
                  </div>
                  <div
                    style={{
                      marginTop: '0.35rem',
                      fontSize: '0.85em',
                      color: 'var(--text-muted)',
                    }}
                  >
                    Actor: {item.actor || 'system'} • Status:{' '}
                    {item.from_status || '-'} → {item.to_status || '-'}
                  </div>
                  {item.details && (
                    <div style={{ marginTop: '0.35rem', fontSize: '0.85em' }}>
                      {item.details}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </>
      )}
      <div
        style={{
          display: 'flex',
          justifyContent: 'flex-end',
          marginTop: '0.75rem',
        }}
      >
        <button type="button" className="btn btn-secondary" onClick={onClose}>
          Close
        </button>
      </div>
    </Modal>
  );
}
