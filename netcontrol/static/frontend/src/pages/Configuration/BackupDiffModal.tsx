import { useConfigBackupDiff } from '@/api/configuration';
import { Modal } from '@/components/Modal';

import { UnifiedDiff } from './UnifiedDiff';
import { formatStamp } from './helpers';

interface Props {
  backupId: number | null;
  onClose: () => void;
}

export function BackupDiffModal({ backupId, onClose }: Props) {
  const query = useConfigBackupDiff(backupId);
  const data = query.data;
  const title = data
    ? `Backup Diff - ${data.hostname || data.ip_address || ''}`
    : 'Backup Diff';

  return (
    <Modal isOpen={backupId != null} onClose={onClose} title={title} size="large">
      {query.isPending && <p className="text-muted">Loading…</p>}
      {query.error && (
        <p style={{ color: 'var(--danger)' }}>
          Failed to load: {(query.error as Error).message}
        </p>
      )}
      {data && (
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
            <span>{data.ip_address || ''}</span>
            <span style={{ opacity: 0.4 }}>|</span>
            <span>Current: {formatStamp(data.captured_at)}</span>
            <span style={{ opacity: 0.4 }}>|</span>
            <span>Previous: {formatStamp(data.previous_captured_at)}</span>
            <span style={{ opacity: 0.4 }}>|</span>
            <span className="drift-diff-added">
              +{data.diff_lines_added || 0}
            </span>
            <span className="drift-diff-removed">
              -{data.diff_lines_removed || 0}
            </span>
          </div>
          <UnifiedDiff diffText={data.diff_text} />
        </>
      )}
      <div
        style={{
          display: 'flex',
          justifyContent: 'flex-end',
          marginTop: '1rem',
        }}
      >
        <button type="button" className="btn btn-secondary" onClick={onClose}>
          Close
        </button>
      </div>
    </Modal>
  );
}
