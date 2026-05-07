import {
  useConfigDriftEvent,
  useUpdateDriftEventStatus,
} from '@/api/configuration';
import { Modal } from '@/components/Modal';

import { UnifiedDiff } from './UnifiedDiff';
import { formatStamp } from './helpers';

interface Props {
  eventId: number | null;
  onClose: () => void;
  onShowHistory: (id: number) => void;
  onShowRevert: (id: number) => void;
}

export function DriftDiffModal({
  eventId,
  onClose,
  onShowHistory,
  onShowRevert,
}: Props) {
  const query = useConfigDriftEvent(eventId);
  const update = useUpdateDriftEventStatus();
  const ev = query.data;
  const title = ev
    ? `Configuration Diff — ${ev.hostname || ''}`
    : 'Configuration Diff';

  return (
    <Modal isOpen={eventId != null} onClose={onClose} title={title} size="large">
      {query.isPending && <p className="text-muted">Loading…</p>}
      {query.error && (
        <p style={{ color: 'var(--danger)' }}>
          Failed to load: {(query.error as Error).message}
        </p>
      )}
      {ev && (
        <>
          <div
            className="drift-event-meta"
            style={{
              marginBottom: '0.75rem',
              display: 'flex',
              gap: '0.5rem',
              flexWrap: 'wrap',
              fontSize: '0.85rem',
            }}
          >
            <span>{ev.ip_address || ''}</span>
            <span style={{ opacity: 0.4 }}>|</span>
            <span>Detected: {formatStamp(ev.detected_at)}</span>
            <span style={{ opacity: 0.4 }}>|</span>
            <span className="drift-diff-added">+{ev.diff_lines_added || 0}</span>
            <span className="drift-diff-removed">
              -{ev.diff_lines_removed || 0}
            </span>
          </div>
          <UnifiedDiff diffText={ev.diff_text} />
          <div
            style={{
              display: 'flex',
              gap: '0.5rem',
              justifyContent: 'flex-end',
              marginTop: '1rem',
              flexWrap: 'wrap',
            }}
          >
            <button
              type="button"
              className="btn btn-secondary"
              onClick={onClose}
            >
              Close
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => {
                onClose();
                onShowHistory(ev.id);
              }}
            >
              Event Log
            </button>
            {ev.status === 'open' && (
              <>
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={update.isPending}
                  onClick={() => {
                    update.mutate(
                      { id: ev.id, status: 'accepted' },
                      { onSuccess: onClose },
                    );
                  }}
                >
                  Accept
                </button>
                <button
                  type="button"
                  className="btn btn-danger"
                  onClick={() => {
                    onClose();
                    onShowRevert(ev.id);
                  }}
                >
                  Revert
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  disabled={update.isPending}
                  onClick={() => {
                    update.mutate(
                      { id: ev.id, status: 'resolved' },
                      { onSuccess: onClose },
                    );
                  }}
                >
                  Resolve
                </button>
              </>
            )}
          </div>
        </>
      )}
    </Modal>
  );
}
