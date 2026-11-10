import {
  useConfigDriftEvent,
  useUpdateDriftEventStatus,
} from '@/api/configuration';
import { BusyButton } from '@/components/BusyButton';
import { useDialogs } from '@/components/DialogProvider-context';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
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
  const { alert } = useDialogs();
  const ev = query.data;
  const busyStatus = update.isPending ? update.variables?.status : undefined;

  const setStatus = (id: number, status: 'accepted' | 'resolved') =>
    update.mutate(
      { id, status },
      {
        onSuccess: onClose,
        onError: (e) => void alert({ message: (e as Error).message, variant: 'error' }),
      },
    );
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
              <BusyButton
                className="btn btn-secondary"
                busy={busyStatus === 'resolved'}
                disabled={update.isPending}
                onClick={() => setStatus(ev.id, 'resolved')}
              >
                Resolve
              </BusyButton>
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
              <BusyButton
                className="btn btn-primary"
                busy={busyStatus === 'accepted'}
                disabled={update.isPending}
                onClick={() => setStatus(ev.id, 'accepted')}
              >
                Accept
              </BusyButton>
            </>
          )}
        </>
      }
    >
      {query.isError && !ev && (
        <QueryError what="the drift event" query={query} />
      )}
      {query.isPending && <LoadingState />}
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
