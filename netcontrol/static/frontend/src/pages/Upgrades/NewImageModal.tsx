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
  const [progress, setProgress] = useState<number | null>(null);

  const [prevOpen, setPrevOpen] = useState(isOpen);
  if (isOpen !== prevOpen) {
    setPrevOpen(isOpen);
    if (!isOpen) {
      setFile(null);
      setError(null);
      setProgress(null);
    }
  }

  useEffect(() => {
    if (!isOpen) upload.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;
    setError(null);
    setProgress(0);
    upload.mutate(
      {
        file,
        onProgress: setProgress,
      },
      {
        onSuccess: () => onClose(),
        onError: (err) => {
          setProgress(null);
          setError((err as Error).message);
        },
      },
    );
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
        {progress !== null && (
          <div style={{ marginTop: '0.75rem' }}>
            <div
              style={{
                height: '6px',
                borderRadius: '3px',
                background: 'var(--border)',
                overflow: 'hidden',
              }}
            >
              <div
                style={{
                  height: '100%',
                  width: `${progress}%`,
                  background: 'var(--accent)',
                  transition: 'width 0.2s ease',
                }}
              />
            </div>
            <p style={{ fontSize: '0.85em', marginTop: '0.35rem', opacity: 0.8 }}>
              Uploading… {progress}%
            </p>
          </div>
        )}
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
