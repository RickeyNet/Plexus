import { useId, useState } from 'react';

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
import { QueryError } from '@/components/QueryError';
import { formatBackendDate } from '@/lib/datetime';
import { usePendingKeys } from '@/lib/usePendingKeys';

import {
  CreateUserModal,
  EditUserModal,
  ResetPasswordModal,
} from './UserModals';

/** A user's effective features, collapsed to a count until expanded. */
function EffectiveFeatures({ features }: { features: string[] }) {
  const [open, setOpen] = useState(false);
  const listId = useId();
  const count = `${features.length} ${features.length === 1 ? 'feature' : 'features'}`;
  return (
    <>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          fontSize: '0.8rem',
          color: 'var(--text-muted)',
          marginTop: '0.25rem',
        }}
      >
        <span>Effective Features: {count}</span>
        {features.length > 0 && (
          <button
            type="button"
            className="btn btn-xs btn-ghost"
            aria-expanded={open}
            aria-controls={open ? listId : undefined}
            onClick={() => setOpen((v) => !v)}
          >
            {open ? 'Hide' : 'Show'}
          </button>
        )}
      </div>
      {open && (
        <div id={listId} style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
          {features.map((name) => (
            <span key={name} className="badge badge-success">
              {name}
            </span>
          ))}
        </div>
      )}
    </>
  );
}

export function UsersTab() {
  const { confirm, alert } = useDialogs();
  const users = useAdminUsers();
  const groups = useAccessGroups();
  const remove = useDeleteAdminUser();
  const deleting = usePendingKeys<number>();

  const [showCreate, setShowCreate] = useState(false);
  const [editUser, setEditUser] = useState<AdminUser | null>(null);
  const [resetUser, setResetUser] = useState<AdminUser | null>(null);

  const groupNames: Record<number, string> = {};
  (groups.data || []).forEach((g) => {
    groupNames[g.id] = g.name;
  });

  return (
    <div className="stack stack-sm">
      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <button
          type="button"
          className="btn btn-sm btn-primary"
          onClick={() => setShowCreate(true)}
        >
          + New User
        </button>
      </div>

      {users.isLoading && <LoadingState text="Loading users…" />}
      {users.isError && !users.data && (
        <QueryError what="users" query={users} />
      )}
      {groups.isError && !groups.data && (
        <QueryError what="access groups" query={groups} />
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
                busy={deleting.isPending(u.id)}
                onClick={async () => {
                  if (!(await confirm({ title: 'Delete user account', message: `Delete @${u.username}?`, confirmLabel: 'Delete' }))) return;
                  await deleting.run(u.id, async () => {
                    try {
                      await remove.mutateAsync(u.id);
                    } catch (e) {
                      void alert({ message: `Failed to delete user: ${(e as Error).message}`, variant: 'error' });
                    }
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
            <EffectiveFeatures features={u.feature_access} />
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
