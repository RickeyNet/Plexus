import { useId, useState } from 'react';

import { useCredentials } from '@/api/compliance';
import { useRestoreBackup } from '@/api/configuration';
import { Callout } from '@/components/Callout';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import { useDialogs } from '@/components/DialogProvider-context';

interface Props {
  backupId: number | null;
  onClose: () => void;
}

export function RestoreBackupModal({ backupId, onClose }: Props) {
  const { alert } = useDialogs();
  const creds = useCredentials();
  const restore = useRestoreBackup();
  const [credId, setCredId] = useState<number | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const formId = useId();

  if (backupId == null) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!credId) return;
    setSaveError(null);
    restore.mutate(
      { backupId, credentialId: credId },
      {
        onSuccess: (res) => {
          onClose();
          const msg = res.validated
            ? `Restore validated successfully for ${res.hostname}. No config differences detected.`
            : `Restore completed for ${res.hostname} but validation found ${res.lines_changed} line(s) changed.\n\n${res.diff_text || ''}`;
          void alert(msg);
        },
        onError: (err) => setSaveError((err as Error).message),
      },
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title="Restore from Backup"
      size="small"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            type="submit"
            form={formId}
            className="btn btn-primary"
            disabled={!credId || restore.isPending}
          >
            {restore.isPending ? 'Restoring…' : 'Restore'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        {creds.isError && !creds.data && (
          <QueryError what="credentials" query={creds} />
        )}
        <p style={{ color: 'var(--warning)', marginBottom: '1rem' }}>
          This will push the backup configuration to the device and validate
          the result.
        </p>
        <label className="form-label">Credential for SSH</label>
        <select
          className="form-select"
          value={credId ?? ''}
          onChange={(e) =>
            setCredId(e.target.value ? Number(e.target.value) : null)
          }
          required
        >
          <option value="">Select…</option>
          {(creds.data || []).map((c) => (
            <option key={c.id} value={c.id}>
              {c.name}
            </option>
          ))}
        </select>
      </form>
    </Modal>
  );
}
