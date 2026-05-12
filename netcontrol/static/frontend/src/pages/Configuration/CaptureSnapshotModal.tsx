import { useMemo, useState } from 'react';

import { useCredentials, useInventoryGroups } from '@/api/compliance';
import {
  useStartCaptureGroupJob,
  useStartCaptureSingleJob,
} from '@/api/configuration';
import { Modal } from '@/components/Modal';

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
    if (!credId) return;
    if (!hostId && !groupId) {
      alert('Please select a host or group');
      return;
    }
    const onSuccess = (res: { job_id: string }) => {
      onClose();
      onJobStarted(res.job_id);
    };
    const onError = (err: unknown) => alert((err as Error).message);
    if (groupId) {
      group.mutate({ groupId, credentialId: credId }, { onSuccess, onError });
    } else if (hostId) {
      single.mutate({ hostId, credentialId: credId }, { onSuccess, onError });
    }
  };

  return (
    <Modal isOpen onClose={onClose} title="Capture Running Config">
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label className="form-label">Single Host</label>
          <select
            className="form-select"
            value={hostId ?? ''}
            onChange={(e) => {
              setHostId(e.target.value ? Number(e.target.value) : null);
              if (e.target.value) setGroupId(null);
            }}
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
          <label className="form-label">Or Entire Group</label>
          <select
            className="form-select"
            value={groupId ?? ''}
            onChange={(e) => {
              setGroupId(e.target.value ? Number(e.target.value) : null);
              if (e.target.value) setHostId(null);
            }}
          >
            <option value="">- Or select entire group -</option>
            {(groups.data || []).map((g) => (
              <option key={g.id} value={g.id}>
                {g.name} ({(g.hosts || []).length} hosts)
              </option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Credentials</label>
          <select
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
            disabled={isPending}
          >
            {isPending ? 'Starting…' : 'Capture'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
