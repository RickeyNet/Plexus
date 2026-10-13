import { FormEvent, useState } from 'react';

import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
import { useCredentials } from '@/api/compliance';
import { useFetchGroupSerials, useFetchHostSerial } from '@/api/inventory';

export type SerialTarget =
  | { mode: 'single'; hostId: number; hostname?: string }
  | { mode: 'bulk'; groupId: number; groupName?: string };

interface Props {
  target: SerialTarget;
  onClose: () => void;
}

export function SerialModal({ target, onClose }: Props) {
  const { alert } = useDialogs();
  const credentials = useCredentials();
  const fetchHost = useFetchHostSerial();
  const fetchGroup = useFetchGroupSerials();
  const [credentialId, setCredentialId] = useState<number | null>(null);

  const list = credentials.data ?? [];
  const isBulk = target.mode === 'bulk';
  const isPending = isBulk ? fetchGroup.isPending : fetchHost.isPending;
  const name = target.mode === 'bulk' ? target.groupName : target.hostname;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (credentialId == null) {
      void alert('Select a credential.');
      return;
    }
    try {
      if (target.mode === 'single') {
        const r = await fetchHost.mutateAsync({ hostId: target.hostId, credentialId });
        onClose();
        void alert(`Serial: ${r.serial_number}`);
        return;
      }
      const r = await fetchGroup.mutateAsync({ groupId: target.groupId, credentialId });
      const ok = r.results.filter((x) => x.ok).length;
      const failed = r.results.length - ok;
      onClose();
      if (failed === 0) {
        void alert(`Fetched ${ok} serial number${ok !== 1 ? 's' : ''}.`);
      } else {
        void alert(
          `${ok} succeeded, ${failed} failed. Check device connectivity.`,
        );
      }
    } catch (err) {
      void alert({ message: (err as Error).message, variant: 'error' });
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={`${isBulk ? 'Fetch All Serials' : 'Fetch Serial Number'}${name ? ` - ${name}` : ''}`}
    >
      <p
        style={{
          marginBottom: '1rem',
          color: 'var(--text-muted)',
          fontSize: '0.88rem',
        }}
      >
        {isBulk ? (
          <>
            Runs <code>show version | include System Serial Number</code> on every
            host in this group via SSH (up to 5 concurrent connections) and stores
            the results.
          </>
        ) : (
          <>
            Runs <code>show version | include System Serial Number</code> via SSH
            and stores the result.
          </>
        )}
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
            <button type="submit" className="btn btn-primary" disabled={isPending}>
              {isPending ? 'Fetching…' : isBulk ? 'Fetch All' : 'Fetch'}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}
