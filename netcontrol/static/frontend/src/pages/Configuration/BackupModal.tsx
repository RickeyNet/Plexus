import { useConfigBackupDetail, useConfigBackupDiff } from '@/api/configuration';
import { Modal } from '@/components/Modal';
import { SegmentedControl } from '@/components/SegmentedControl';

import { UnifiedDiff } from './UnifiedDiff';
import { type BackupView, backupDiffAvailable, formatStamp } from './helpers';

interface Props {
  backupId: number | null;
  view: BackupView;
  onViewChange: (view: BackupView) => void;
  onClose: () => void;
}

export function BackupModal({ backupId, view, onViewChange, onClose }: Props) {
  const detail = useConfigBackupDetail(backupId);
  const canDiff = backupDiffAvailable(detail.data?.status);
  const activeView: BackupView = canDiff ? view : 'config';
  const host = detail.data?.hostname || detail.data?.ip_address || '';

  return (
    <Modal
      isOpen={backupId != null}
      onClose={onClose}
      title={host ? `Backup - ${host}` : 'Backup'}
      size="large"
    >
      <SegmentedControl
        aria-label="Backup view"
        value={activeView}
        onChange={onViewChange}
        options={[
          { key: 'config', label: 'Config' },
          {
            key: 'diff',
            label: 'Diff vs previous',
            disabled: !canDiff,
            title: canDiff ? undefined : 'Only successful backups can be diffed',
          },
        ]}
      />
      <div style={{ marginTop: '0.75rem' }}>
        {activeView === 'diff' ? (
          <DiffView backupId={backupId} />
        ) : (
          <ConfigView query={detail} />
        )}
      </div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '1rem' }}>
        <button type="button" className="btn btn-secondary" onClick={onClose}>
          Close
        </button>
      </div>
    </Modal>
  );
}

function ConfigView({ query }: { query: ReturnType<typeof useConfigBackupDetail> }) {
  if (query.isPending) return <p className="text-muted">Loading…</p>;
  if (query.error) {
    return <p style={{ color: 'var(--danger)' }}>Failed to load: {(query.error as Error).message}</p>;
  }
  const data = query.data;
  return (
    <>
      <div style={{ fontSize: '0.85em', marginBottom: '0.75rem', color: 'var(--text-muted)' }}>
        Captured: {formatStamp(data.captured_at)} • Method: {data.capture_method || '-'} • Status:{' '}
        {data.status}
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
  );
}

function DiffView({ backupId }: { backupId: number | null }) {
  const query = useConfigBackupDiff(backupId);
  if (query.isPending) return <p className="text-muted">Loading…</p>;
  if (query.error) {
    return <p style={{ color: 'var(--danger)' }}>Failed to load: {(query.error as Error).message}</p>;
  }
  const data = query.data;
  return (
    <>
      <div
        className="drift-event-meta"
        style={{ marginBottom: '0.75rem', display: 'flex', gap: '0.5rem', flexWrap: 'wrap', fontSize: '0.85rem' }}
      >
        <span>{data.ip_address || ''}</span>
        <span style={{ opacity: 0.4 }}>|</span>
        <span>Current: {formatStamp(data.captured_at)}</span>
        <span style={{ opacity: 0.4 }}>|</span>
        <span>Previous: {formatStamp(data.previous_captured_at) || 'none'}</span>
        <span style={{ opacity: 0.4 }}>|</span>
        <span className="drift-diff-added">+{data.diff_lines_added || 0}</span>
        <span className="drift-diff-removed">-{data.diff_lines_removed || 0}</span>
      </div>
      <UnifiedDiff diffText={data.diff_text} />
    </>
  );
}
