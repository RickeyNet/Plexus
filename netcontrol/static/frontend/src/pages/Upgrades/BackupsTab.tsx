import {
  type ConfigBackup,
  upgradeBackupDownloadUrl,
  useDeleteUpgradeBackup,
  useUpgradeBackups,
} from '@/api/upgrades';

import { formatBackupTimestamp, formatBytes } from './helpers';

export function BackupsTab() {
  const query = useUpgradeBackups();
  const remove = useDeleteUpgradeBackup();

  if (query.isPending) return <p className="text-muted">Loading…</p>;
  if (query.error) {
    return (
      <p style={{ color: 'var(--danger)' }}>
        Failed to load backups: {(query.error as Error).message}
      </p>
    );
  }

  const backups = query.data || [];
  if (!backups.length) {
    return (
      <div className="empty-state" style={{ padding: '2rem' }}>
        No config backups yet. Backups are created during the Prestage phase of
        an upgrade campaign.
      </div>
    );
  }

  const handleDelete = (b: ConfigBackup) => {
    if (!confirm(`Delete backup file "${b.filename}"? This cannot be undone.`)) return;
    remove.mutate(b.filename, {
      onError: (e) => alert(`Delete failed: ${(e as Error).message}`),
    });
  };

  return (
    <table className="data-table" style={{ width: '100%' }}>
      <thead>
        <tr>
          <th style={{ textAlign: 'left' }}>Filename</th>
          <th style={{ textAlign: 'left' }}>Size</th>
          <th style={{ textAlign: 'left' }}>Date</th>
          <th style={{ textAlign: 'left' }}>Actions</th>
        </tr>
      </thead>
      <tbody>
        {backups.map((b) => (
          <tr key={b.filename}>
            <td style={{ textAlign: 'left' }}>
              <code>{b.filename}</code>
            </td>
            <td style={{ textAlign: 'left' }}>{formatBytes(b.size)}</td>
            <td style={{ textAlign: 'left', whiteSpace: 'nowrap' }}>
              {formatBackupTimestamp(b.modified)}
            </td>
            <td style={{ textAlign: 'left', whiteSpace: 'nowrap' }}>
              <a
                className="btn btn-sm btn-secondary"
                href={upgradeBackupDownloadUrl(b.filename)}
                download={b.filename}
              >
                Download
              </a>{' '}
              <button
                type="button"
                className="btn btn-sm btn-danger"
                onClick={() => handleDelete(b)}
                disabled={remove.isPending}
              >
                Delete
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
