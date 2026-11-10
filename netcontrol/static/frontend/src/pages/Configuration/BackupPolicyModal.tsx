import { useId, useState } from 'react';

import { groupLabel } from '@/api/inventory';
import { useAuthStatus } from '@/api/auth';
import { useCredentials, useInventoryGroups } from '@/api/compliance';
import {
  type ConfigBackupPolicy,
  useCreateBackupPolicy,
  useUpdateBackupPolicy,
} from '@/api/configuration';
import { useServiceCredentialsList } from '@/api/settings';
import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';

interface Props {
  policy: ConfigBackupPolicy | null; // null = create mode
  onClose: () => void;
}

export function BackupPolicyModal({ policy, onClose }: Props) {
  const isEdit = policy != null;
  const groups = useInventoryGroups();
  const creds = useCredentials();
  const auth = useAuthStatus();
  const isAdmin = auth.data?.role === 'admin';
  // The backend allows service credentials on backup policies (they're the
  // intended account for unattended work), but /api/credentials only lists
  // the user's own. Admins get the service list as a second optgroup.
  const serviceCreds = useServiceCredentialsList(isAdmin);
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
  const [nameError, setNameError] = useState<string | null>(null);
  const [credError, setCredError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const formId = useId();

  // Seed default selections from server data when it arrives (create mode only).
  const [prevGroups, setPrevGroups] = useState(groups.data);
  if (groups.data !== prevGroups) {
    setPrevGroups(groups.data);
    if (!isEdit && groups.data && groupId == null && groups.data.length > 0) {
      setGroupId(groups.data[0].id);
    }
  }
  const [prevCreds, setPrevCreds] = useState(creds.data);
  if (creds.data !== prevCreds) {
    setPrevCreds(creds.data);
    if (!isEdit && creds.data && credId == null && creds.data.length > 0) {
      setCredId(creds.data[0].id);
    }
  }

  const ownCreds = creds.data ?? [];
  const svcCreds = isAdmin ? (serviceCreds.data ?? []) : [];
  // Edit mode: the stored credential may not be accessible from this account
  // (owned by another user, or a service cred seen by a non-admin). A
  // controlled <select> whose value matches no option *renders* as if the
  // first option were chosen but would still submit the stale id, so the
  // save 403s while looking correct. Detect that once all lists have
  // settled, blank the select, and force an explicit re-pick.
  const listsSettled =
    creds.data != null &&
    auth.data != null &&
    (!isAdmin || serviceCreds.data != null || serviceCreds.isError);
  const staleCred =
    isEdit &&
    listsSettled &&
    credId != null &&
    !ownCreds.some((c) => c.id === credId) &&
    !svcCreds.some((c) => c.id === credId);

  const isPending = create.isPending || update.isPending;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setNameError(null);
    setCredError(null);
    setSaveError(null);
    if (!name.trim()) {
      setNameError('Name is required');
      return;
    }
    const interval_seconds = Math.max(1, hours) * 3600;
    if (isEdit) {
      if (!credId || staleCred) {
        setCredError('Choose a credential for this policy');
        return;
      }
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
          onError: (err) => setSaveError((err as Error).message),
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
          onError: (err) => setSaveError((err as Error).message),
        },
      );
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={isEdit ? 'Edit Backup Policy' : 'Create Backup Policy'}
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={isPending}>
            {isPending ? 'Saving…' : isEdit ? 'Save' : 'Create'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        {!isEdit && groups.isError && !groups.data && (
          <QueryError what="inventory groups" query={groups} />
        )}
        {creds.isError && !creds.data && (
          <QueryError what="credentials" query={creds} />
        )}
        <label className="form-label">Policy Name</label>
        <input
          className="form-input"
          placeholder="Daily backup"
          value={name}
          onChange={(e) => {
            setName(e.target.value);
            setNameError(null);
          }}
          aria-invalid={!!nameError}
          required
        />
        <FieldError>{nameError}</FieldError>
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
                  {groupLabel(g)}
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
          value={staleCred ? '' : (credId ?? '')}
          onChange={(e) => {
            setCredId(e.target.value ? Number(e.target.value) : null);
            setCredError(null);
          }}
          aria-invalid={!!credError}
          required
        >
          {(staleCred || credId == null) && (
            <option value="" disabled>
              Select a credential…
            </option>
          )}
          {svcCreds.length > 0 ? (
            <>
              <optgroup label="My credentials">
                {ownCreds.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </optgroup>
              <optgroup label="Service credentials">
                {svcCreds.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </optgroup>
            </>
          ) : (
            ownCreds.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))
          )}
        </select>
        <FieldError>{credError}</FieldError>
        {staleCred && (
          <p
            style={{
              fontSize: '0.85em',
              color: 'var(--warning)',
              marginTop: '0.5rem',
            }}
          >
            The credential saved on this policy isn&apos;t accessible from
            your account, so scheduled backups are failing. Choose a
            replacement before saving.
          </p>
        )}
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
      </form>
    </Modal>
  );
}
