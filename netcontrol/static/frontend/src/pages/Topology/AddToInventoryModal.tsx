import { useState } from 'react';

import { useAddHost, useCreateInventoryGroup, useInventoryGroupsLite } from '@/api/topology';
import { Modal } from '@/components/Modal';

interface Props {
  isOpen: boolean;
  hostname: string;
  ip: string;
  extNodeId: string | number | null;
  onClose: () => void;
  onAdded: (info: { groupId: number; groupName: string; newHostId: number; extNodeId: string | number | null }) => void;
}

export function AddToInventoryModal({ isOpen, hostname, ip, extNodeId, onClose, onAdded }: Props) {
  const groupsQuery = useInventoryGroupsLite();
  const groups = groupsQuery.data ?? [];
  const addHost = useAddHost();
  const createGroup = useCreateInventoryGroup();

  const [showNewGroup, setShowNewGroup] = useState(false);
  const [newGroupName, setNewGroupName] = useState('');
  const [selectedGroupId, setSelectedGroupId] = useState<number | ''>('');
  const [error, setError] = useState<string | null>(null);

  if (isOpen && selectedGroupId === '' && groups.length > 0) {
    setSelectedGroupId(groups[0].id);
  }

  const hasGroups = groups.length > 0;
  const useNewGroupForm = !hasGroups || showNewGroup;

  async function handleCreateGroup() {
    if (!newGroupName.trim()) {
      setError('Group name is required');
      return;
    }
    setError(null);
    try {
      const created = await createGroup.mutateAsync({ name: newGroupName.trim() });
      setSelectedGroupId(created.id);
      setShowNewGroup(false);
      setNewGroupName('');
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function handleConfirm() {
    if (typeof selectedGroupId !== 'number') return;
    const groupName = groups.find((g) => g.id === selectedGroupId)?.name ?? '';
    setError(null);
    try {
      const result = await addHost.mutateAsync({
        groupId: selectedGroupId,
        hostname,
        ipAddress: ip,
        deviceType: 'unknown',
      });
      onAdded({ groupId: selectedGroupId, groupName, newHostId: result.id, extNodeId });
      onClose();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Add to Inventory">
      <div style={{ padding: '0.5rem' }}>
        <p style={{ marginBottom: '1rem', color: 'var(--text-muted)' }}>
          Adding <strong>{hostname}</strong> ({ip})
        </p>
        {!useNewGroupForm && (
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '1rem' }}>
            <select
              className="form-select"
              style={{ flex: 1 }}
              value={selectedGroupId}
              onChange={(e) => setSelectedGroupId(parseInt(e.target.value, 10))}
            >
              {groups.map((g) => (
                <option key={g.id} value={g.id}>{g.name}</option>
              ))}
            </select>
            <button
              type="button"
              className="btn btn-sm btn-secondary"
              title="Create new group"
              onClick={() => setShowNewGroup(true)}
            >
              +
            </button>
          </div>
        )}
        {useNewGroupForm && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginBottom: '1rem' }}>
            <label style={{ fontSize: '0.85rem', fontWeight: 500 }}>New Group Name</label>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <input
                className="form-input"
                type="text"
                placeholder="Group name"
                style={{ flex: 1 }}
                value={newGroupName}
                onChange={(e) => setNewGroupName(e.target.value)}
              />
              <button
                type="button"
                className="btn btn-sm btn-primary"
                onClick={handleCreateGroup}
                disabled={createGroup.isPending}
              >
                {createGroup.isPending ? 'Creating…' : 'Create'}
              </button>
              {hasGroups && (
                <button type="button" className="btn btn-sm btn-secondary" onClick={() => setShowNewGroup(false)}>
                  Cancel
                </button>
              )}
            </div>
          </div>
        )}
        {error && <div style={{ color: 'var(--danger)', marginBottom: '0.75rem' }}>{error}</div>}
        {!useNewGroupForm && (
          <button
            type="button"
            className="btn btn-primary"
            style={{ width: '100%' }}
            onClick={handleConfirm}
            disabled={addHost.isPending || typeof selectedGroupId !== 'number'}
          >
            {addHost.isPending ? 'Adding…' : 'Add to Group'}
          </button>
        )}
      </div>
    </Modal>
  );
}
