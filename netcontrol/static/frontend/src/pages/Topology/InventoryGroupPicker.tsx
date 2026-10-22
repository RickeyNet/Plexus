import { useState } from 'react';

import { groupLabel } from '@/api/inventory';
import { useCreateInventoryGroup, type InventoryGroupLite } from '@/api/topology';

const NEW_GROUP = '__new__';

interface Props {
  groups: InventoryGroupLite[];
  /** The chosen group, or null when there is none yet. */
  value: number | null;
  onChange: (groupId: number) => void;
  onError: (message: string | null) => void;
}

/**
 * Inventory group select with a "New group…" choice that creates the group
 * (via the group-create API) and selects it. Shared by the Topology page's
 * single and bulk "Add to inventory" dialogs.
 */
export function InventoryGroupPicker({ groups, value, onChange, onError }: Props) {
  const createGroup = useCreateInventoryGroup();
  const [creating, setCreating] = useState(false);
  const [newGroupName, setNewGroupName] = useState('');
  const showForm = creating || groups.length === 0;

  async function handleCreate() {
    const name = newGroupName.trim();
    if (!name) {
      onError('Group name is required');
      return;
    }
    onError(null);
    try {
      const created = await createGroup.mutateAsync({ name });
      onChange(created.id);
      setCreating(false);
      setNewGroupName('');
    } catch (e) {
      onError((e as Error).message);
    }
  }

  if (!showForm) {
    return (
      <select
        className="form-select"
        aria-label="Inventory group"
        style={{ width: '100%' }}
        value={value ?? ''}
        onChange={(e) => {
          if (e.target.value === NEW_GROUP) setCreating(true);
          else onChange(parseInt(e.target.value, 10));
        }}
      >
        {groups.map((g) => (
          <option key={g.id} value={g.id}>{groupLabel(g)}</option>
        ))}
        <option value={NEW_GROUP}>New group…</option>
      </select>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
      <label style={{ fontSize: '0.85rem', fontWeight: 500 }}>New Group Name</label>
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
        <input
          className="form-input"
          type="text"
          placeholder="Group name"
          style={{ flex: '1 1 10rem', minWidth: 0 }}
          value={newGroupName}
          onChange={(e) => setNewGroupName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault();
              void handleCreate();
            }
          }}
        />
        <button
          type="button"
          className="btn btn-sm btn-primary"
          onClick={handleCreate}
          disabled={createGroup.isPending}
        >
          {createGroup.isPending ? 'Creating…' : 'Create'}
        </button>
        {groups.length > 0 && (
          <button type="button" className="btn btn-sm btn-secondary" onClick={() => setCreating(false)}>
            Cancel
          </button>
        )}
      </div>
    </div>
  );
}
