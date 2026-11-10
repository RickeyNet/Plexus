import { useId, useMemo, useState } from 'react';

import { groupLabel } from '@/api/inventory';
import { useCredentials, useInventoryGroups } from '@/api/compliance';
import {
  useStartCaptureGroupJob,
  useStartCaptureSingleJob,
} from '@/api/configuration';
import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';

interface Props {
  onClose: () => void;
  onJobStarted: (jobId: string) => void;
}

export function CaptureSnapshotModal({ onClose, onJobStarted }: Props) {
  const groups = useInventoryGroups(true);
  const creds = useCredentials();
  const single = useStartCaptureSingleJob();
  const group = useStartCaptureGroupJob();
  const [hostId, setHostId] = useState<number | null>(null);
  const [groupId, setGroupId] = useState<number | null>(null);
  const [credId, setCredId] = useState<number | null>(null);
  const [targetError, setTargetError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const formId = useId();

  const hosts = useMemo(() => {
    const list: { id: number; hostname: string; ip_address: string }[] = [];
    for (const g of groups.data || []) {
      for (const h of g.hosts || []) list.push(h);
    }
    return list;
  }, [groups.data]);

  const isPending = single.isPending || group.isPending;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setTargetError(null);
    setSaveError(null);
    if (!credId) return;
    if (!hostId && !groupId) {
      setTargetError('Please select a host or group');
      return;
    }
    const onSuccess = (res: { job_id: string }) => {
      onClose();
      onJobStarted(res.job_id);
    };
    const onError = (err: unknown) => setSaveError((err as Error).message);
    if (groupId) {
      group.mutate({ groupId, credentialId: credId }, { onSuccess, onError });
    } else if (hostId) {
      single.mutate({ hostId, credentialId: credId }, { onSuccess, onError });
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title="Capture Running Config"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            type="submit"
            form={formId}
            className="btn btn-primary"
            disabled={isPending}
          >
            {isPending ? 'Starting…' : 'Capture'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        {groups.isError && !groups.data && (
          <QueryError what="inventory groups" query={groups} />
        )}
        {creds.isError && !creds.data && (
          <QueryError what="credentials" query={creds} />
        )}
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-host`}>Single Host</label>
          <select
            id={`${formId}-host`}
            className="form-select"
            value={hostId ?? ''}
            onChange={(e) => {
              setHostId(e.target.value ? Number(e.target.value) : null);
              if (e.target.value) setGroupId(null);
              setTargetError(null);
            }}
            aria-invalid={!!targetError}
          >
            <option value="">Select a host…</option>
            {hosts.map((h) => (
              <option key={h.id} value={h.id}>
                {h.hostname} ({h.ip_address})
              </option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-group`}>Or Entire Group</label>
          <select
            id={`${formId}-group`}
            className="form-select"
            value={groupId ?? ''}
            onChange={(e) => {
              setGroupId(e.target.value ? Number(e.target.value) : null);
              if (e.target.value) setHostId(null);
              setTargetError(null);
            }}
            aria-invalid={!!targetError}
          >
            <option value="">- Or select entire group -</option>
            {(groups.data || []).map((g) => (
              <option key={g.id} value={g.id}>
                {groupLabel(g)} ({(g.hosts || []).length} hosts)
              </option>
            ))}
          </select>
          <FieldError>{targetError}</FieldError>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-credential`}>Credentials</label>
          <select
            id={`${formId}-credential`}
            className="form-select"
            value={credId ?? ''}
            onChange={(e) =>
              setCredId(e.target.value ? Number(e.target.value) : null)
            }
            required
          >
            <option value="">Select credentials…</option>
            {(creds.data || []).map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
        </div>
      </form>
    </Modal>
  );
}
