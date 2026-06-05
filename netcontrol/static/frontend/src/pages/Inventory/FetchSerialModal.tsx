import { FormEvent, useState } from 'react';

import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
import { useCredentials } from '@/api/compliance';
import { useFetchHostSerial } from '@/api/inventory';

interface Props {
  hostId: number;
  hostname?: string;
  onClose: () => void;
}

export function FetchSerialModal({ hostId, hostname, onClose }: Props) {
  const { alert } = useDialogs();
  const credentials = useCredentials();
  const fetch = useFetchHostSerial();
  const [credentialId, setCredentialId] = useState<number | null>(null);

  const list = credentials.data ?? [];

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (credentialId == null) {
      void alert('Select a credential.');
      return;
    }
    try {
      const r = await fetch.mutateAsync({ hostId, credentialId });
      onClose();
      void alert(`Serial: ${r.serial_number}`);
    } catch (err) {
      void alert({ message: (err as Error).message, variant: 'error' });
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={`Fetch Serial Number${hostname ? ` - ${hostname}` : ''}`}
    >
      <p
        style={{
          marginBottom: '1rem',
          color: 'var(--text-muted)',
          fontSize: '0.88rem',
        }}
      >
        Runs <code>show version | include System Serial Number</code> via SSH and
        stores the result.
      </p>
      {credentials.isPending ? (
        <p className="text-muted">Loading credentials…</p>
      ) : list.length === 0 ? (
        <p className="text-muted">
          No credentials configured. Add one under Settings → Credentials.
        </p>
      ) : (
        <form onSubmit={submit}>
          <div className="form-group">
            <label className="form-label">Credential</label>
            <select
              className="form-select"
              value={credentialId == null ? '' : String(credentialId)}
              onChange={(e) =>
                setCredentialId(e.target.value ? Number(e.target.value) : null)
              }
              required
            >
              <option value="">- Select -</option>
              {list.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                </option>
              ))}
            </select>
          </div>
          <div
            style={{
              display: 'flex',
              gap: '0.5rem',
              justifyContent: 'flex-end',
              marginTop: '1rem',
            }}
          >
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={fetch.isPending}
            >
              {fetch.isPending ? 'Fetching…' : 'Fetch'}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}
