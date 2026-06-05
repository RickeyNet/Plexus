import { useState } from 'react';

import { useCredentials } from '@/api/compliance';
import { useRevertDriftEvent } from '@/api/configuration';
import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';

interface Props {
  eventId: number | null;
  onClose: () => void;
  onJobStarted: (jobId: string) => void;
}

export function RevertDriftModal({ eventId, onClose, onJobStarted }: Props) {
  const { alert } = useDialogs();
  const creds = useCredentials();
  const revert = useRevertDriftEvent();
  const [credentialId, setCredentialId] = useState<number | null>(null);

  if (eventId == null) return null;

  return (
    <Modal isOpen onClose={onClose} title="Revert Device to Baseline">
      <p style={{ marginBottom: '1rem', color: 'var(--text-muted)' }}>
        This will push the baseline configuration back to the device,
        overwriting any unauthorized changes. The device will be re-captured
        afterward to verify compliance.
      </p>
      {creds.isPending && <p className="text-muted">Loading credentials…</p>}
      {creds.data && (
        <>
          <div className="form-group" style={{ marginBottom: '1rem' }}>
            <label className="form-label">SSH Credential</label>
            <select
              className="form-select"
              value={credentialId ?? ''}
              onChange={(e) =>
                setCredentialId(e.target.value ? Number(e.target.value) : null)
              }
            >
              <option value="">Select…</option>
              {creds.data.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                </option>
              ))}
            </select>
          </div>
          <div
            style={{
              display: 'flex',
              justifyContent: 'flex-end',
              gap: '0.5rem',
            }}
          >
            <button
              type="button"
              className="btn btn-secondary"
              onClick={onClose}
            >
              Cancel
            </button>
            <button
              type="button"
              className="btn btn-danger"
              disabled={credentialId == null || revert.isPending}
              onClick={() => {
                if (credentialId == null) return;
                revert.mutate(
                  { eventId, credentialId },
                  {
                    onSuccess: (res) => {
                      onClose();
                      onJobStarted(res.job_id);
                    },
                    onError: (e) => {
                      void alert({ message: (e as Error).message, variant: 'error' });
                    },
                  },
                );
              }}
            >
              {revert.isPending ? 'Starting…' : 'Revert Device'}
            </button>
          </div>
        </>
      )}
    </Modal>
  );
}
