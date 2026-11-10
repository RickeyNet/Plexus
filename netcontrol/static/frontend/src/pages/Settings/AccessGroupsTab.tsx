import { useState } from 'react';

import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  AccessGroup,
  AdminCapabilities,
  useAccessGroups,
  useDeleteAccessGroup,
} from '@/api/settings';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { AccessGroupModal } from './AccessGroupModal';

export function AccessGroupsTab({
  capabilities,
}: {
  capabilities: AdminCapabilities;
}) {
  const { confirm, alert } = useDialogs();
  const groups = useAccessGroups();
  const remove = useDeleteAccessGroup();
  const deleting = usePendingKeys<number>();

  const [showCreate, setShowCreate] = useState(false);
  const [editGroup, setEditGroup] = useState<AccessGroup | null>(null);

  return (
    <div className="stack stack-sm">
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}
      >
        <h3 style={{ margin: 0 }}>Access Groups</h3>
        <button className="btn btn-sm btn-primary" onClick={() => setShowCreate(true)}>
          + New Group
        </button>
      </div>

      {groups.isLoading && <LoadingState text="Loading groups…" />}
      {groups.isError && !groups.data && (
        <QueryError what="access groups" query={groups} />
      )}
      {groups.data && groups.data.length === 0 && (
        <EmptyState compact message="No access groups defined." />
      )}

      {(groups.data || []).map((g) => (
        <div
          key={g.id}
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
              <strong>{g.name}</strong>
              <div className="card-description">{g.description || ''}</div>
              <div className="card-description">
                {g.member_count || 0} member(s)
              </div>
            </div>
            <div style={{ display: 'flex', gap: '0.4rem' }}>
              <button
                className="btn btn-sm btn-secondary"
                onClick={() => setEditGroup(g)}
              >
                Edit
              </button>
              <DeleteButton
                busy={deleting.isPending(g.id)}
                onClick={async () => {
                  if (!(await confirm({ title: 'Delete access group', message: `Delete group '${g.name}'?`, confirmLabel: 'Delete' }))) return;
                  await deleting.run(g.id, async () => {
                    try {
                      await remove.mutateAsync(g.id);
                    } catch (e) {
                      void alert({ message: `Failed to delete group: ${(e as Error).message}`, variant: 'error' });
                    }
                  });
                }}
              />
            </div>
          </div>
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: '0.4rem',
              marginTop: '0.5rem',
            }}
          >
            {g.feature_keys.length === 0 ? (
              <span className="card-description">No features assigned</span>
            ) : (
              g.feature_keys.map((feature) => (
                <span key={feature} className="badge badge-info">
                  {feature}
                </span>
              ))
            )}
          </div>
        </div>
      ))}

      {showCreate && (
        <AccessGroupModal
          mode="create"
          features={capabilities.feature_flags}
          onClose={() => setShowCreate(false)}
        />
      )}
      {editGroup && (
        <AccessGroupModal
          mode="edit"
          group={editGroup}
          features={capabilities.feature_flags}
          onClose={() => setEditGroup(null)}
        />
      )}
    </div>
  );
}
