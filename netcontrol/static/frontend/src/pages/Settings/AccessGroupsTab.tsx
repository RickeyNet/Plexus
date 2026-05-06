import { useState } from 'react';

import {
  AccessGroup,
  AdminCapabilities,
  useAccessGroups,
  useDeleteAccessGroup,
} from '@/api/settings';

import { AccessGroupModal } from './AccessGroupModal';

export function AccessGroupsTab({
  capabilities,
}: {
  capabilities: AdminCapabilities;
}) {
  const groups = useAccessGroups();
  const remove = useDeleteAccessGroup();

  const [showCreate, setShowCreate] = useState(false);
  const [editGroup, setEditGroup] = useState<AccessGroup | null>(null);

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
        <h3 style={{ margin: 0 }}>Access Groups</h3>
        <button className="btn btn-sm btn-primary" onClick={() => setShowCreate(true)}>
          + New Group
        </button>
      </div>

      {groups.isLoading && <p className="text-muted">Loading groups…</p>}
      {groups.isError && (
        <div className="error">
          Failed to load groups: {(groups.error as Error).message}
        </div>
      )}
      {groups.data && groups.data.length === 0 && (
        <p className="text-muted">No access groups defined.</p>
      )}

      {(groups.data || []).map((g) => (
        <div
          key={g.id}
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
              <button
                className="btn btn-sm"
                style={{ color: 'var(--danger)' }}
                onClick={() => {
                  if (!confirm(`Delete group '${g.name}'?`)) return;
                  remove.mutate(g.id, {
                    onError: (e) =>
                      alert(`Failed to delete group: ${(e as Error).message}`),
                  });
                }}
              >
                Delete
              </button>
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
