import { FormEvent, useState } from 'react';

import { Modal } from '@/components/Modal';
import { useCredentials } from '@/api/compliance';
import { useFetchGroupSerials } from '@/api/inventory';

interface Props {
  groupId: number;
  groupName?: string;
  onClose: () => void;
}

export function BulkSerialModal({ groupId, groupName, onClose }: Props) {
  const credentials = useCredentials();
  const fetch = useFetchGroupSerials();
  const [credentialId, setCredentialId] = useState<number | null>(null);

  const list = credentials.data ?? [];

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (credentialId == null) {
      alert('Select a credential.');
      return;
    }
    try {
      const r = await fetch.mutateAsync({ groupId, credentialId });
      const ok = r.results.filter((x) => x.ok).length;
      const failed = r.results.length - ok;
      onClose();
      if (failed === 0) {
        alert(`Fetched ${ok} serial number${ok !== 1 ? 's' : ''}.`);
      } else {
        alert(
          `${ok} succeeded, ${failed} failed. Check device connectivity.`,
        );
      }
    } catch (err) {
      alert((err as Error).message);
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={`Fetch All Serials${groupName ? ` - ${groupName}` : ''}`}
    >
      <p
        style={{
          marginBottom: '1rem',
          color: 'var(--text-muted)',
          fontSize: '0.88rem',
        }}
      >
        Runs <code>show version | include System Serial Number</code> on every
        host in this group via SSH (up to 5 concurrent connections) and stores
        the results.
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
              {fetch.isPending ? 'Fetching…' : 'Fetch All'}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}
