import { useEffect, useState } from 'react';

import { useUploadUpgradeImage } from '@/api/upgrades';
import { Modal } from '@/components/Modal';

interface Props {
  isOpen: boolean;
  onClose: () => void;
}

export function NewImageModal({ isOpen, onClose }: Props) {
  const upload = useUploadUpgradeImage();
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isOpen) {
      setFile(null);
      setError(null);
      upload.reset();
    }
  }, [isOpen, upload]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;
    setError(null);
    upload.mutate(file, {
      onSuccess: () => onClose(),
      onError: (err) => setError((err as Error).message),
    });
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Upload Software Image">
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label className="form-label">IOS-XE Image File (.bin)</label>
          <input
            type="file"
            className="form-input"
            accept=".bin,.SPA.bin"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            required
          />
        </div>
        <p style={{ fontSize: '0.85em', opacity: 0.7 }}>
          Image will be stored on the server and MD5 hash will be computed
          automatically. Model pattern and version will be auto-detected from
          the filename.
        </p>
        {error && (
          <p style={{ color: 'var(--danger)', marginTop: '0.5rem' }}>{error}</p>
        )}
        <div
          style={{
            display: 'flex',
            justifyContent: 'flex-end',
            gap: '0.5rem',
            marginTop: '1rem',
          }}
        >
          <button
            type="button"
            className="btn btn-secondary"
            onClick={onClose}
            disabled={upload.isPending}
          >
            Cancel
          </button>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={!file || upload.isPending}
          >
            {upload.isPending ? 'Uploading…' : 'Upload'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
