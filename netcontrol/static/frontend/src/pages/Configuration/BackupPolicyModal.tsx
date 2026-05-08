import { useEffect, useState } from 'react';

import { useCredentials, useInventoryGroups } from '@/api/compliance';
import {
  type ConfigBackupPolicy,
  useCreateBackupPolicy,
  useUpdateBackupPolicy,
} from '@/api/configuration';
import { Modal } from '@/components/Modal';

interface Props {
  policy: ConfigBackupPolicy | null; // null = create mode
  onClose: () => void;
}

export function BackupPolicyModal({ policy, onClose }: Props) {
  const isEdit = policy != null;
  const groups = useInventoryGroups();
  const creds = useCredentials();
  const create = useCreateBackupPolicy();
  const update = useUpdateBackupPolicy();

  const [name, setName] = useState(policy?.name ?? '');
  const [enabled, setEnabled] = useState(policy?.enabled ?? true);
  const [groupId, setGroupId] = useState<number | null>(policy?.group_id ?? null);
  const [credId, setCredId] = useState<number | null>(
    policy?.credential_id ?? null,
  );
  const [hours, setHours] = useState(
    policy ? Math.round(policy.interval_seconds / 3600) : 24,
  );
  const [retentionDays, setRetentionDays] = useState(policy?.retention_days ?? 30);

  useEffect(() => {
    if (!isEdit && groups.data && groupId == null && groups.data.length > 0) {
      setGroupId(groups.data[0].id);
    }
    if (!isEdit && creds.data && credId == null && creds.data.length > 0) {
      setCredId(creds.data[0].id);
    }
  }, [isEdit, groups.data, creds.data, groupId, credId]);

  const isPending = create.isPending || update.isPending;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      alert('Name is required');
      return;
    }
    const interval_seconds = Math.max(1, hours) * 3600;
    if (isEdit) {
      if (!credId) return;
      update.mutate(
        {
          id: policy.id,
          data: {
            name: name.trim(),
            enabled,
            credential_id: credId,
            interval_seconds,
            retention_days: retentionDays,
          },
        },
        {
          onSuccess: () => onClose(),
          onError: (err) => alert((err as Error).message),
        },
      );
    } else {
      if (!groupId || !credId) return;
      create.mutate(
        {
          name: name.trim(),
          group_id: groupId,
          credential_id: credId,
          interval_seconds,
          retention_days: retentionDays,
        },
        {
          onSuccess: () => onClose(),
          onError: (err) => alert((err as Error).message),
        },
      );
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={isEdit ? 'Edit Backup Policy' : 'Create Backup Policy'}
    >
      <form onSubmit={handleSubmit}>
        <label className="form-label">Policy Name</label>
        <input
          className="form-input"
          placeholder="Daily backup"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />
        {isEdit ? (
          <>
            <label className="form-label" style={{ marginTop: '0.75rem' }}>
              Enabled
            </label>
            <select
              className="form-select"
              value={enabled ? 'true' : 'false'}
              onChange={(e) => setEnabled(e.target.value === 'true')}
            >
              <option value="true">Enabled</option>
              <option value="false">Disabled</option>
            </select>
          </>
        ) : (
          <>
            <label className="form-label" style={{ marginTop: '0.75rem' }}>
              Inventory Group
            </label>
            <select
              className="form-select"
              value={groupId ?? ''}
              onChange={(e) =>
                setGroupId(e.target.value ? Number(e.target.value) : null)
              }
              required
            >
              {(groups.data || []).map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </>
        )}
        <label className="form-label" style={{ marginTop: '0.75rem' }}>
          Credential
        </label>
        <select
          className="form-select"
          value={credId ?? ''}
          onChange={(e) =>
            setCredId(e.target.value ? Number(e.target.value) : null)
          }
          required
        >
          {(creds.data || []).map((c) => (
            <option key={c.id} value={c.id}>
              {c.name}
            </option>
          ))}
        </select>
        <label className="form-label" style={{ marginTop: '0.75rem' }}>
          Interval (hours)
        </label>
        <input
          className="form-input"
          type="number"
          min={1}
          max={168}
          value={hours}
          onChange={(e) => setHours(Number(e.target.value || '24'))}
        />
        <label className="form-label" style={{ marginTop: '0.75rem' }}>
          Retention (days)
        </label>
        <input
          className="form-input"
          type="number"
          min={1}
          max={365}
          value={retentionDays}
          onChange={(e) => setRetentionDays(Number(e.target.value || '30'))}
        />
        <div
          style={{
            marginTop: '1rem',
            display: 'flex',
            justifyContent: 'flex-end',
            gap: '0.5rem',
          }}
        >
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn btn-primary" disabled={isPending}>
            {isPending ? 'Saving…' : isEdit ? 'Save' : 'Create'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
