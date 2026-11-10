import {
  useConfigDriftEvent,
  useUpdateDriftEventStatus,
} from '@/api/configuration';
import { Callout } from '@/components/Callout';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { formatBackendDateTime } from '@/lib/datetime';

import { UnifiedDiff } from './UnifiedDiff';

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
    ? `Configuration Diff - ${ev.hostname || ''}`
    : 'Configuration Diff';

  return (
    <Modal
      isOpen={eventId != null}
      onClose={onClose}
      title={title}
      size="large"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
          {ev && (
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
          )}
          {ev?.status === 'open' && (
            <>
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
            </>
          )}
        </>
      }
    >
      {query.isPending && <LoadingState />}
      {query.error && (
        <Callout tone="danger">
          Failed to load: {(query.error as Error).message}
        </Callout>
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
            <span>Detected: {formatBackendDateTime(ev.detected_at, '')}</span>
            <span style={{ opacity: 0.4 }}>|</span>
            <span className="drift-diff-added">+{ev.diff_lines_added || 0}</span>
            <span className="drift-diff-removed">
              -{ev.diff_lines_removed || 0}
            </span>
          </div>
          <UnifiedDiff diffText={ev.diff_text} />
        </>
      )}
    </Modal>
  );
}
