import { useEffect, useState } from 'react';

import { type UpgradeImage, useUpdateUpgradeImage } from '@/api/upgrades';
import { Modal } from '@/components/Modal';

interface Props {
  image: UpgradeImage | null;
  onClose: () => void;
}

export function EditImageModal({ image, onClose }: Props) {
  const update = useUpdateUpgradeImage();
  const [modelPattern, setModelPattern] = useState('');
  const [version, setVersion] = useState('');
  const [notes, setNotes] = useState('');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (image) {
      setModelPattern(image.model_pattern || '');
      setVersion(image.version || '');
      setNotes(image.notes || '');
      setError(null);
      update.reset();
    }
    // `update` is stable across renders only by identity-spec — depend on
    // image alone so we don't reset the form on every parent re-render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [image]);

  if (!image) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    update.mutate(
      {
        id: image.id,
        body: {
          model_pattern: modelPattern,
          version,
          platform: image.platform || 'iosxe',
          notes,
        },
      },
      {
        onSuccess: () => onClose(),
        onError: (err) => setError((err as Error).message),
      },
    );
  };

  return (
    <Modal isOpen onClose={onClose} title="Edit Image">
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label className="form-label">Filename</label>
          <input className="form-input" value={image.filename} disabled />
        </div>
        <div className="form-group">
          <label className="form-label">
            Model Pattern (e.g. "9200", "C9300", "C9200L")
          </label>
          <input
            className="form-input"
            value={modelPattern}
            onChange={(e) => setModelPattern(e.target.value)}
          />
        </div>
        <div className="form-group">
          <label className="form-label">Version</label>
          <input
            className="form-input"
            value={version}
            onChange={(e) => setVersion(e.target.value)}
          />
        </div>
        <div className="form-group">
          <label className="form-label">Notes</label>
          <textarea
            className="form-input"
            rows={3}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
          />
        </div>
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
            disabled={update.isPending}
          >
            Cancel
          </button>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={update.isPending}
          >
            {update.isPending ? 'Saving…' : 'Save'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
