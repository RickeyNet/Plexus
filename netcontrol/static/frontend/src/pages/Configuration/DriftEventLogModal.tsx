import {
  useConfigDriftEvent,
  useConfigDriftEventHistory,
} from '@/api/configuration';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import { formatBackendDateTime } from '@/lib/datetime';


interface Props {
  eventId: number | null;
  onClose: () => void;
}

export function DriftEventLogModal({ eventId, onClose }: Props) {
  const ev = useConfigDriftEvent(eventId);
  const history = useConfigDriftEventHistory(eventId, 500);

  const failed = ev.isError && !ev.data ? ev : history.isError && !history.data ? history : null;
  const isPending = !failed && (ev.isPending || history.isPending);
  const title = ev.data
    ? `Drift Event Log - ${ev.data.hostname || ev.data.ip_address || ''}`
    : 'Drift Event Log';
  const entries = history.data || [];

  return (
    <Modal
      isOpen={eventId != null}
      onClose={onClose}
      title={title}
      size="large"
      footer={
        <button type="button" className="btn btn-secondary" onClick={onClose}>
          Close
        </button>
      }
    >
      {failed && (
        <QueryError what="the drift event log" query={failed} />
      )}
      {isPending && <LoadingState />}
      {ev.data && !failed && (
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
            <span>Detected: {formatBackendDateTime(ev.data.detected_at, '')}</span>
          </div>
          <div className="stack stack-sm" style={{ maxHeight: '60vh', overflow: 'auto' }}>
            {entries.length === 0 ? (
              <div
                className="card"
                style={{
                  textAlign: 'center',
                  color: 'var(--text-muted)',
                }}
              >
                No history entries recorded yet.
              </div>
            ) : (
              entries.map((item, i) => (
                <div key={i} className="card card-sm">
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
                      {formatBackendDateTime(item.created_at, '') || '-'}
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
    </Modal>
  );
}
