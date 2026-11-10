import { useState } from 'react';

import {
  type ConfigBackup,
  upgradeBackupDownloadUrl,
  useDeleteUpgradeBackup,
  useUpgradeBackups,
} from '@/api/upgrades';
import { AlertDialog } from '@/components/AlertDialog';
import { Callout } from '@/components/Callout';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import { DeleteButton } from '@/components/DeleteButton';
import { LoadingState } from '@/components/LoadingState';
import { formatBackendDateTime } from '@/lib/datetime';

import { formatBytes } from './helpers';

export function BackupsTab() {
  const query = useUpgradeBackups();
  const remove = useDeleteUpgradeBackup();
  const [deleteTarget, setDeleteTarget] = useState<ConfigBackup | null>(null);
  const [alert, setAlert] = useState<{ title: string; message: string } | null>(
    null,
  );

  if (query.isPending) return <LoadingState />;
  if (query.error) {
    return (
      <Callout tone="danger">
        Failed to load backups: {(query.error as Error).message}
      </Callout>
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

  const handleDeleteConfirm = () => {
    if (!deleteTarget) return;
    remove.mutate(deleteTarget.filename, {
      onSuccess: () => setDeleteTarget(null),
      onError: (e) => {
        setDeleteTarget(null);
        setAlert({
          title: 'Delete failed',
          message: (e as Error).message,
        });
      },
    });
  };

  return (
    <>
    <table className="data-table">
      <thead>
        <tr>
          <th>Filename</th>
          <th>Size</th>
          <th>Date</th>
          <th>Actions</th>
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
              {formatBackendDateTime(b.modified, '')}
            </td>
            <td style={{ textAlign: 'left', whiteSpace: 'nowrap' }}>
              <a
                className="btn btn-sm btn-secondary"
                href={upgradeBackupDownloadUrl(b.filename)}
                download={b.filename}
              >
                Download
              </a>{' '}
              <DeleteButton onClick={() => setDeleteTarget(b)} disabled={remove.isPending} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
    <ConfirmDialog
      isOpen={deleteTarget !== null}
      title="Delete backup file?"
      message={
        <>
          Delete <code>{deleteTarget?.filename}</code>? This cannot be undone.
        </>
      }
      confirmLabel="Delete"
      loading={remove.isPending}
      onCancel={() => {
        if (!remove.isPending) setDeleteTarget(null);
      }}
      onConfirm={handleDeleteConfirm}
    />
    <AlertDialog
      isOpen={alert !== null}
      title={alert?.title ?? ''}
      message={alert?.message ?? ''}
      variant="error"
      onClose={() => setAlert(null)}
    />
    </>
  );
}
