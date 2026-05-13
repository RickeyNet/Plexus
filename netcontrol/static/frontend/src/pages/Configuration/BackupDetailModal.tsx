import { useConfigBackupDetail } from '@/api/configuration';
import { Modal } from '@/components/Modal';

import { formatStamp } from './helpers';

interface Props {
  backupId: number | null;
  onClose: () => void;
}

export function BackupDetailModal({ backupId, onClose }: Props) {
  const query = useConfigBackupDetail(backupId);
  const data = query.data;
  const title = data
    ? `Backup Detail - ${data.hostname || data.ip_address || ''}`
    : 'Backup Detail';

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
            style={{
              fontSize: '0.85em',
              marginBottom: '0.75rem',
              color: 'var(--text-muted)',
            }}
          >
            Captured: {formatStamp(data.captured_at)} •{' '}
            Method: {data.capture_method || '-'} • Status: {data.status}
          </div>
          <pre
            style={{
              background: 'var(--bg-secondary)',
              padding: '1rem',
              borderRadius: 8,
              maxHeight: 480,
              overflow: 'auto',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.8rem',
              whiteSpace: 'pre-wrap',
              margin: 0,
            }}
          >
            {data.config_text || '(empty)'}
          </pre>
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
