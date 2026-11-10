import { useId, useState } from 'react';

import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import {
  AccessGroup,
  AdminUser,
  useCreateAdminUser,
  useResetAdminUserPassword,
  useSetAdminUserGroups,
  useUpdateAdminUser,
} from '@/api/settings';

function GroupCheckboxes({
  groups,
  selected,
  onChange,
  labelledBy,
}: {
  groups: AccessGroup[];
  selected: number[];
  onChange: (next: number[]) => void;
  labelledBy: string;
}) {
  if (groups.length === 0) {
    return <span className="card-description">Create access groups first.</span>;
  }
  const set = new Set(selected);
  return (
    <div
      role="group"
      aria-labelledby={labelledBy}
      style={{
        display: 'grid',
        gap: '0.35rem',
        maxHeight: 160,
        overflow: 'auto',
        border: '1px solid var(--border)',
        borderRadius: '0.375rem',
        padding: '0.6rem',
      }}
    >
      {groups.map((g) => (
        <label
          key={g.id}
          style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}
        >
          <input
            type="checkbox"
            checked={set.has(g.id)}
            onChange={(e) => {
              const next = new Set(set);
              if (e.target.checked) next.add(g.id);
              else next.delete(g.id);
              onChange(Array.from(next));
            }}
          />
          <span>{g.name}</span>
        </label>
      ))}
    </div>
  );
}

export function CreateUserModal({
  groups,
  onClose,
}: {
  groups: AccessGroup[];
  onClose: () => void;
}) {
  const create = useCreateAdminUser();
  const setGroups = useSetAdminUserGroups();
  const fid = useId();

  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPasswords, setShowPasswords] = useState(false);
  const [role, setRole] = useState<'admin' | 'user'>('user');
  const [groupIds, setGroupIds] = useState<number[]>([]);
  const [error, setError] = useState<string | null>(null);

  const passwordsMatch = password === confirm;
  const saving = create.isPending || setGroups.isPending;
  const submitDisabled =
    !username.trim() ||
    username.trim().length < 3 ||
    password.length < 8 ||
    !passwordsMatch ||
    saving;

  return (
    <Modal
      isOpen
      onClose={onClose}
      title="Create User Account"
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel="Create"
          primaryBusy={saving}
          primaryBusyLabel="Creating…"
          primaryDisabled={submitDisabled}
          onPrimary={() => {
            setError(null);
            create.mutate(
              {
                username: username.trim(),
                password,
                display_name: displayName.trim(),
                role,
                group_ids: groupIds,
              },
              {
                onSuccess: (created) => {
                  if (groupIds.length > 0 && created?.id != null) {
                    setGroups.mutate(
                      { id: created.id, groupIds },
                      { onSettled: () => onClose() },
                    );
                  } else {
                    onClose();
                  }
                },
                onError: (e) => setError((e as Error).message),
              },
            );
          }}
        />
      }
    >
      <div className="form-group">
        <label className="form-label" htmlFor={`${fid}-username`}>Username</label>
        <input
          id={`${fid}-username`}
          className="form-input"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          minLength={3}
        />
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor={`${fid}-display-name`}>Display Name</label>
        <input
          id={`${fid}-display-name`}
          className="form-input"
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
        />
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor={`${fid}-password`}>Password</label>
        <input
          id={`${fid}-password`}
          type={showPasswords ? 'text' : 'password'}
          className="form-input"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          minLength={8}
        />
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor={`${fid}-confirm-password`}>Confirm Password</label>
        <input
          id={`${fid}-confirm-password`}
          type={showPasswords ? 'text' : 'password'}
          className="form-input"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          minLength={8}
          aria-invalid={!!confirm && !passwordsMatch}
        />
        <FieldError>{confirm && !passwordsMatch && 'Passwords do not match'}</FieldError>
      </div>
      <div className="form-group">
        <label style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
          <input
            type="checkbox"
            checked={showPasswords}
            onChange={(e) => setShowPasswords(e.target.checked)}
          />
          <span>Show passwords</span>
        </label>
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor={`${fid}-role`}>Role</label>
        <select
          id={`${fid}-role`}
          className="form-select"
          value={role}
          onChange={(e) => setRole(e.target.value as 'admin' | 'user')}
        >
          <option value="user">User</option>
          <option value="admin">Admin</option>
        </select>
      </div>
      <div className="form-group">
        <span className="form-label" id={`${fid}-groups`}>Access Groups</span>
        <GroupCheckboxes
          groups={groups}
          selected={groupIds}
          onChange={setGroupIds}
          labelledBy={`${fid}-groups`}
        />
      </div>
      {error && <Callout tone="danger">{error}</Callout>}
    </Modal>
  );
}

export function EditUserModal({
  user,
  groups,
  onClose,
}: {
  user: AdminUser;
  groups: AccessGroup[];
  onClose: () => void;
}) {
  const update = useUpdateAdminUser();
  const setGroups = useSetAdminUserGroups();
  const fid = useId();

  const [username, setUsername] = useState(user.username);
  const [displayName, setDisplayName] = useState(user.display_name || '');
  const [role, setRole] = useState<'admin' | 'user'>(
    user.role === 'admin' ? 'admin' : 'user',
  );
  const [groupIds, setGroupIds] = useState<number[]>(user.group_ids);
  const [neverExpires, setNeverExpires] = useState<boolean>(!!user.session_never_expires);
  const [error, setError] = useState<string | null>(null);

  const saving = update.isPending || setGroups.isPending;
  const submitDisabled =
    !username.trim() || username.trim().length < 3 || saving;

  return (
    <Modal
      isOpen
      onClose={onClose}
      title="Edit User Account"
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel="Save"
          primaryBusy={saving}
          primaryBusyLabel="Saving…"
          primaryDisabled={submitDisabled}
          onPrimary={() => {
            setError(null);
            update.mutate(
              {
                id: user.id,
                data: {
                  username: username.trim(),
                  display_name: displayName.trim(),
                  role,
                  session_never_expires: neverExpires,
                },
              },
              {
                onSuccess: () => {
                  setGroups.mutate(
                    { id: user.id, groupIds },
                    {
                      onSuccess: () => onClose(),
                      onError: (e) => setError((e as Error).message),
                    },
                  );
                },
                onError: (e) => setError((e as Error).message),
              },
            );
          }}
        />
      }
    >
      <div className="form-group">
        <label className="form-label" htmlFor={`${fid}-username`}>Username</label>
        <input
          id={`${fid}-username`}
          className="form-input"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          minLength={3}
        />
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor={`${fid}-display-name`}>Display Name</label>
        <input
          id={`${fid}-display-name`}
          className="form-input"
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
        />
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor={`${fid}-role`}>Role</label>
        <select
          id={`${fid}-role`}
          className="form-select"
          value={role}
          onChange={(e) => setRole(e.target.value as 'admin' | 'user')}
        >
          <option value="user">User</option>
          <option value="admin">Admin</option>
        </select>
      </div>
      <div className="form-group">
        <span className="form-label" id={`${fid}-groups`}>Access Groups</span>
        <GroupCheckboxes
          groups={groups}
          selected={groupIds}
          onChange={setGroupIds}
          labelledBy={`${fid}-groups`}
        />
      </div>
      <div className="form-group">
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <input
            type="checkbox"
            checked={neverExpires}
            onChange={(e) => setNeverExpires(e.target.checked)}
          />
          <span>Session never expires</span>
        </label>
        <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
          Bypasses the global idle timeout. Use only for read-only kiosk
          accounts (smart boards, NOC walls).
        </div>
      </div>
      {error && <Callout tone="danger">{error}</Callout>}
    </Modal>
  );
}

export function ResetPasswordModal({
  user,
  onClose,
}: {
  user: AdminUser;
  onClose: () => void;
}) {
  const reset = useResetAdminUserPassword();
  const fid = useId();
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);

  const submitDisabled = password.length < 8 || reset.isPending;

  return (
    <Modal
      isOpen
      onClose={onClose}
      title="Reset User Password"
      size="small"
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel="Reset Password"
          primaryBusy={reset.isPending}
          primaryBusyLabel="Resetting…"
          primaryDisabled={submitDisabled}
          onPrimary={() => {
            setError(null);
            reset.mutate(
              { id: user.id, newPassword: password },
              {
                onSuccess: () => onClose(),
                onError: (e) => setError((e as Error).message),
              },
            );
          }}
        />
      }
    >
      <p className="card-description" style={{ marginBottom: '0.75rem' }}>
        Set a new login password for @{user.username}.
      </p>
      <div className="form-group">
        <label className="form-label" htmlFor={`${fid}-new-password`}>New Password</label>
        <input
          id={`${fid}-new-password`}
          type="password"
          className="form-input"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          minLength={8}
        />
      </div>
      {error && <Callout tone="danger">{error}</Callout>}
    </Modal>
  );
}
