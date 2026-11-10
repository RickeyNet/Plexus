import { useEffect, useId, useState } from 'react';

import { type UpgradeImage, useUpdateUpgradeImage } from '@/api/upgrades';
import { Callout } from '@/components/Callout';
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
  const [prevImage, setPrevImage] = useState(image);
  const formId = useId();

  // Re-seed the form when a different image is opened. Adjusting state during
  // render (guarded by the previous value) is React's recommended alternative
  // to a setState-in-effect and avoids an extra render pass.
  if (image !== prevImage) {
    setPrevImage(image);
    if (image) {
      setModelPattern(image.model_pattern || '');
      setVersion(image.version || '');
      setNotes(image.notes || '');
      setError(null);
    }
  }

  useEffect(() => {
    // Clear any stale mutation state when a new image is opened. This is an
    // external-store side effect, so it stays in an effect.
    if (image) update.reset();
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
    <Modal
      isOpen
      onClose={onClose}
      title="Edit Image"
      footer={
        <>
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
            form={formId}
            className="btn btn-primary"
            disabled={update.isPending}
          >
            {update.isPending ? 'Saving…' : 'Save'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit}>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-filename`}>Filename</label>
          <input id={`${formId}-filename`} className="form-input" value={image.filename} disabled />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-model-pattern`}>
            Model Pattern (e.g. "9200", "C9300", "C9200L")
          </label>
          <input
            id={`${formId}-model-pattern`}
            className="form-input"
            value={modelPattern}
            onChange={(e) => setModelPattern(e.target.value)}
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-version`}>Version</label>
          <input
            id={`${formId}-version`}
            className="form-input"
            value={version}
            onChange={(e) => setVersion(e.target.value)}
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-notes`}>Notes</label>
          <textarea
            id={`${formId}-notes`}
            className="form-input"
            rows={3}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
          />
        </div>
        {error && <Callout tone="danger">{error}</Callout>}
      </form>
    </Modal>
  );
}
