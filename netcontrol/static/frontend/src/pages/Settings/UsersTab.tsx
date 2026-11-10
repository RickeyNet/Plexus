import { useState } from 'react';

import { Callout } from '@/components/Callout';
import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  AdminUser,
  useAccessGroups,
  useAdminUsers,
  useDeleteAdminUser,
} from '@/api/settings';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { formatBackendDate } from '@/lib/datetime';

import {
  CreateUserModal,
  EditUserModal,
  ResetPasswordModal,
} from './UserModals';

export function UsersTab() {
  const { confirm, alert } = useDialogs();
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
    <div className="stack stack-sm">
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}
      >
        <h3 style={{ margin: 0 }}>User Accounts</h3>
        <button className="btn btn-sm btn-primary" onClick={() => setShowCreate(true)}>
          + New User
        </button>
      </div>

      {users.isLoading && <LoadingState text="Loading users…" />}
      {users.isError && (
        <Callout tone="danger">
          Failed to load users: {(users.error as Error).message}
        </Callout>
      )}
      {users.data && users.data.length === 0 && (
        <EmptyState compact message="No user accounts found." />
      )}

      {(users.data || []).map((u) => (
        <div
          key={u.id}
          className="card-inset"
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
                @{u.username} · {u.role} · Created {formatBackendDate(u.created_at)}
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
              <DeleteButton
                onClick={async () => {
                  if (!(await confirm({ title: 'Delete user account', message: `Delete @${u.username}?`, confirmLabel: 'Delete' }))) return;
                  remove.mutate(u.id, {
                    onError: (e) => {
                      void alert({ message: `Failed to delete user: ${(e as Error).message}`, variant: 'error' });
                    },
                  });
                }}
              />
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
