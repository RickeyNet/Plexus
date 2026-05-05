import { useState } from 'react';

import {
  AdminUser,
  useAccessGroups,
  useAdminUsers,
  useDeleteAdminUser,
} from '@/api/settings';

import {
  CreateUserModal,
  EditUserModal,
  ResetPasswordModal,
} from './UserModals';

const formatDate = (raw?: string): string => {
  if (!raw) return '—';
  const date = new Date(raw.endsWith('Z') ? raw : raw + 'Z');
  if (Number.isNaN(date.getTime())) return raw;
  return date.toLocaleDateString();
};

export function UsersTab() {
  const users = useAdminUsers();
  const groups = useAccessGroups();
  const remove = useDeleteAdminUser();

  const [showCreate, setShowCreate] = useState(false);
  const [editUser, setEditUser] = useState<AdminUser | null>(null);
  const [resetUser, setResetUser] = useState<AdminUser | null>(null);

  const groupNames: Record<number, string> = {};
  (groups.data || []).forEach((g) => {
    groupNames[g.id] = g.name;
  });

  return (
    <div>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '0.75rem',
        }}
      >
        <h3 style={{ margin: 0 }}>User Accounts</h3>
        <button className="btn btn-sm btn-primary" onClick={() => setShowCreate(true)}>
          + New User
        </button>
      </div>

      {users.isLoading && <p className="text-muted">Loading users…</p>}
      {users.isError && (
        <div className="error">
          Failed to load users: {(users.error as Error).message}
        </div>
      )}
      {users.data && users.data.length === 0 && (
        <p className="text-muted">No user accounts found.</p>
      )}

      {(users.data || []).map((u) => (
        <div
          key={u.id}
          className="card"
          style={{ marginBottom: '0.75rem', padding: '1rem' }}
        >
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'flex-start',
              flexWrap: 'wrap',
              gap: '0.5rem',
            }}
          >
            <div>
              <strong>{u.display_name || u.username}</strong>
              <div className="card-description">
                @{u.username} · {u.role} · Created {formatDate(u.created_at)}
              </div>
            </div>
            <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
              <button
                className="btn btn-sm btn-secondary"
                onClick={() => setEditUser(u)}
              >
                Edit
              </button>
              <button
                className="btn btn-sm btn-secondary"
                onClick={() => setResetUser(u)}
              >
                Reset Password
              </button>
              <button
                className="btn btn-sm"
                style={{ color: 'var(--danger)' }}
                onClick={() => {
                  if (!confirm(`Delete @${u.username}?`)) return;
                  remove.mutate(u.id, {
                    onError: (e) =>
                      alert(`Failed to delete user: ${(e as Error).message}`),
                  });
                }}
              >
                Delete
              </button>
            </div>
          </div>
          <div style={{ display: 'grid', gap: '0.4rem', marginTop: '0.5rem' }}>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Access Groups
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
              {u.group_ids.length === 0 ? (
                <span className="card-description">
                  No groups assigned (full default access)
                </span>
              ) : (
                u.group_ids.map((gid) => (
                  <span key={gid} className="badge badge-info">
                    {groupNames[gid] || `Group ${gid}`}
                  </span>
                ))
              )}
            </div>
            <div
              style={{
                fontSize: '0.8rem',
                color: 'var(--text-muted)',
                marginTop: '0.25rem',
              }}
            >
              Effective Features
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
              {u.feature_access.map((name) => (
                <span key={name} className="badge badge-success">
                  {name}
                </span>
              ))}
            </div>
          </div>
        </div>
      ))}

      {showCreate && (
        <CreateUserModal
          groups={groups.data || []}
          onClose={() => setShowCreate(false)}
        />
      )}
      {editUser && (
        <EditUserModal
          user={editUser}
          groups={groups.data || []}
          onClose={() => setEditUser(null)}
        />
      )}
      {resetUser && (
        <ResetPasswordModal
          user={resetUser}
          onClose={() => setResetUser(null)}
        />
      )}
    </div>
  );
}
