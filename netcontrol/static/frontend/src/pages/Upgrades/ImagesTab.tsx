import { useState } from 'react';

import {
  type UpgradeImage,
  useDeleteUpgradeImage,
  useUpgradeImages,
} from '@/api/upgrades';
import { AlertDialog } from '@/components/AlertDialog';
import { ConfirmDialog } from '@/components/ConfirmDialog';

import { EditImageModal } from './EditImageModal';
import { NewImageModal } from './NewImageModal';
import { formatBackupTimestamp, formatBytes } from './helpers';

export function ImagesTab() {
  const query = useUpgradeImages();
  const remove = useDeleteUpgradeImage();
  const [uploadOpen, setUploadOpen] = useState(false);
  const [editing, setEditing] = useState<UpgradeImage | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<UpgradeImage | null>(null);
  const [alert, setAlert] = useState<{ title: string; message: string } | null>(
    null,
  );

  if (query.isPending) return <p className="text-muted">Loading…</p>;
  if (query.error) {
    return (
      <p style={{ color: 'var(--danger)' }}>
        Failed to load images: {(query.error as Error).message}
      </p>
    );
  }

  const images = query.data || [];

  const handleDeleteConfirm = () => {
    if (!deleteTarget) return;
    remove.mutate(deleteTarget.id, {
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
    <div>
      <div
        style={{
          display: 'flex',
          justifyContent: 'flex-end',
          marginBottom: '0.75rem',
        }}
      >
        <button
          type="button"
          className="btn btn-sm btn-primary"
          onClick={() => setUploadOpen(true)}
        >
          Upload Image
        </button>
      </div>

      {images.length === 0 ? (
        <div className="empty-state" style={{ padding: '2rem' }}>
          No software images uploaded yet.
        </div>
      ) : (
        <table className="data-table" style={{ width: '100%' }}>
          <thead>
            <tr>
              <th style={{ textAlign: 'left' }}>Filename</th>
              <th style={{ textAlign: 'left' }}>Version</th>
              <th style={{ textAlign: 'left' }}>Model Pattern</th>
              <th style={{ textAlign: 'left' }}>Size</th>
              <th style={{ textAlign: 'left' }}>MD5</th>
              <th style={{ textAlign: 'left' }}>Uploaded</th>
              <th style={{ textAlign: 'left' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {images.map((img) => (
              <tr key={img.id}>
                <td style={{ textAlign: 'left' }}>
                  <code>{img.filename}</code>
                </td>
                <td style={{ textAlign: 'left' }}>{img.version || '-'}</td>
                <td style={{ textAlign: 'left' }}>
                  <code>{img.model_pattern || '-'}</code>
                </td>
                <td style={{ textAlign: 'left' }}>{formatBytes(img.file_size)}</td>
                <td style={{ textAlign: 'left' }} title={img.md5_hash}>
                  <code>{img.md5_hash ? `${img.md5_hash.slice(0, 12)}…` : ''}</code>
                </td>
                <td style={{ textAlign: 'left', whiteSpace: 'nowrap' }}>
                  {formatBackupTimestamp(img.created_at)}
                </td>
                <td style={{ textAlign: 'left', whiteSpace: 'nowrap' }}>
                  <button
                    type="button"
                    className="btn btn-sm btn-secondary"
                    onClick={() => setEditing(img)}
                  >
                    Edit
                  </button>{' '}
                  <button
                    type="button"
                    className="btn btn-sm btn-danger"
                    onClick={() => setDeleteTarget(img)}
                    disabled={remove.isPending}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <NewImageModal
        isOpen={uploadOpen}
        onClose={() => setUploadOpen(false)}
      />
      <EditImageModal
        image={editing}
        onClose={() => setEditing(null)}
      />
      <ConfirmDialog
        isOpen={deleteTarget !== null}
        title="Delete software image?"
        message={
          <>
            Delete <code>{deleteTarget?.filename}</code>? This removes the file
            from the server.
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
    </div>
  );
}
