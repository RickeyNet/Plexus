import { FormEvent, useId, useState } from 'react';

import { Callout } from '@/components/Callout';
import { EmptyState } from '@/components/EmptyState';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
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
  const [credentialError, setCredentialError] = useState<string | null>(null);
  const [runError, setRunError] = useState<string | null>(null);
  const formId = useId();

  const list = credentials.data ?? [];
  const isBulk = target.mode === 'bulk';
  const isPending = isBulk ? fetchGroup.isPending : fetchHost.isPending;
  const name = target.mode === 'bulk' ? target.groupName : target.hostname;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setRunError(null);
    if (credentialId == null) {
      setCredentialError('Select a credential.');
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
      setRunError((err as Error).message);
    }
  };

  const showForm = !credentials.isPending && list.length > 0;

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={`${isBulk ? 'Fetch All Serials' : 'Fetch Serial Number'}${name ? ` - ${name}` : ''}`}
      size="small"
      footer={
        showForm && (
          <>
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" form={formId} className="btn btn-primary" disabled={isPending}>
              {isPending ? 'Fetching…' : isBulk ? 'Fetch All' : 'Fetch'}
            </button>
          </>
        )
      }
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
        <LoadingState text="Loading credentials…" />
      ) : list.length === 0 ? (
        <EmptyState compact message="No credentials configured. Add one under Settings → Credentials." />
      ) : (
        <form id={formId} onSubmit={submit}>
          {runError && <Callout tone="danger">{runError}</Callout>}
          <div className="form-group">
            <label className="form-label">Credential</label>
            <select
              className="form-select"
              value={credentialId == null ? '' : String(credentialId)}
              onChange={(e) => {
                setCredentialId(e.target.value ? Number(e.target.value) : null);
                setCredentialError(null);
              }}
              required
              aria-invalid={!!credentialError}
            >
              <option value="">- Select -</option>
              {list.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                </option>
              ))}
            </select>
            <FieldError>{credentialError}</FieldError>
          </div>
        </form>
      )}
    </Modal>
  );
}
