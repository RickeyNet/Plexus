import { useState } from 'react';

import { Modal } from '@/components/Modal';
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
}: {
  groups: AccessGroup[];
  selected: number[];
  onChange: (next: number[]) => void;
}) {
  if (groups.length === 0) {
    return <span className="card-description">Create access groups first.</span>;
  }
  const set = new Set(selected);
  return (
    <div
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

function ModalActions({
  onClose,
  primaryLabel,
  primaryDisabled,
  onPrimary,
}: {
  onClose: () => void;
  primaryLabel: string;
  primaryDisabled?: boolean;
  onPrimary: () => void;
}) {
  return (
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
        type="button"
        className="btn btn-primary"
        disabled={primaryDisabled}
        onClick={onPrimary}
      >
        {primaryLabel}
      </button>
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

  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPasswords, setShowPasswords] = useState(false);
  const [role, setRole] = useState<'admin' | 'user'>('user');
  const [groupIds, setGroupIds] = useState<number[]>([]);
  const [error, setError] = useState<string | null>(null);

  const passwordsMatch = password === confirm;
  const submitDisabled =
    !username.trim() ||
    username.trim().length < 3 ||
    password.length < 8 ||
    !passwordsMatch ||
    create.isPending;

  return (
    <Modal isOpen onClose={onClose} title="Create User Account">
      <div className="form-group">
        <label className="form-label">Username</label>
        <input
          className="form-input"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          minLength={3}
        />
      </div>
      <div className="form-group">
        <label className="form-label">Display Name</label>
        <input
          className="form-input"
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
        />
      </div>
      <div className="form-group">
        <label className="form-label">Password</label>
        <input
          type={showPasswords ? 'text' : 'password'}
          className="form-input"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          minLength={8}
        />
      </div>
      <div className="form-group">
        <label className="form-label">Confirm Password</label>
        <input
          type={showPasswords ? 'text' : 'password'}
          className="form-input"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          minLength={8}
        />
        {confirm && !passwordsMatch && (
          <div className="error" style={{ marginTop: '0.25rem' }}>
            Passwords do not match
          </div>
        )}
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
        <label className="form-label">Role</label>
        <select
          className="form-select"
          value={role}
          onChange={(e) => setRole(e.target.value as 'admin' | 'user')}
        >
          <option value="user">User</option>
          <option value="admin">Admin</option>
        </select>
      </div>
      <div className="form-group">
        <label className="form-label">Access Groups</label>
        <GroupCheckboxes groups={groups} selected={groupIds} onChange={setGroupIds} />
      </div>
      {error && <div className="error">{error}</div>}
      <ModalActions
        onClose={onClose}
        primaryLabel={create.isPending ? 'Creating…' : 'Create'}
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

  const [username, setUsername] = useState(user.username);
  const [displayName, setDisplayName] = useState(user.display_name || '');
  const [role, setRole] = useState<'admin' | 'user'>(
    user.role === 'admin' ? 'admin' : 'user',
  );
  const [groupIds, setGroupIds] = useState<number[]>(user.group_ids);
  const [error, setError] = useState<string | null>(null);

  const submitDisabled =
    !username.trim() || username.trim().length < 3 || update.isPending;

  return (
    <Modal isOpen onClose={onClose} title="Edit User Account">
      <div className="form-group">
        <label className="form-label">Username</label>
        <input
          className="form-input"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          minLength={3}
        />
      </div>
      <div className="form-group">
        <label className="form-label">Display Name</label>
        <input
          className="form-input"
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
        />
      </div>
      <div className="form-group">
        <label className="form-label">Role</label>
        <select
          className="form-select"
          value={role}
          onChange={(e) => setRole(e.target.value as 'admin' | 'user')}
        >
          <option value="user">User</option>
          <option value="admin">Admin</option>
        </select>
      </div>
      <div className="form-group">
        <label className="form-label">Access Groups</label>
        <GroupCheckboxes groups={groups} selected={groupIds} onChange={setGroupIds} />
      </div>
      {error && <div className="error">{error}</div>}
      <ModalActions
        onClose={onClose}
        primaryLabel={update.isPending ? 'Saving…' : 'Save'}
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
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);

  const submitDisabled = password.length < 8 || reset.isPending;

  return (
    <Modal isOpen onClose={onClose} title="Reset User Password">
      <p className="card-description" style={{ marginBottom: '0.75rem' }}>
        Set a new login password for @{user.username}.
      </p>
      <div className="form-group">
        <label className="form-label">New Password</label>
        <input
          type="password"
          className="form-input"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          minLength={8}
        />
      </div>
      {error && <div className="error">{error}</div>}
      <ModalActions
        onClose={onClose}
        primaryLabel={reset.isPending ? 'Resetting…' : 'Reset Password'}
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
    </Modal>
  );
}
