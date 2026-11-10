import { useMemo, useState } from 'react';

import { useAddHost, useInventoryGroupsLite } from '@/api/topology';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';

import { InventoryGroupPicker } from './InventoryGroupPicker';

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
  const groups = useMemo(() => groupsQuery.data ?? [], [groupsQuery.data]);
  const addHost = useAddHost();

  const [pickedGroupId, setPickedGroupId] = useState<number | null>(null);
  const selectedGroupId = pickedGroupId ?? groups[0]?.id ?? null;
  const [error, setError] = useState<string | null>(null);

  async function handleConfirm() {
    if (selectedGroupId == null) return;
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
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Add to Inventory"
      size="small"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={handleConfirm}
            disabled={addHost.isPending || selectedGroupId == null}
          >
            {addHost.isPending ? 'Adding…' : 'Add to Group'}
          </button>
        </>
      }
    >
      <div style={{ padding: '0.5rem' }}>
        <p style={{ marginBottom: '1rem', color: 'var(--text-muted)' }}>
          Adding <strong>{hostname}</strong> ({ip})
        </p>
        <InventoryGroupPicker
          groups={groups}
          value={selectedGroupId}
          onChange={setPickedGroupId}
          onError={setError}
        />
        <FieldError>{error}</FieldError>
      </div>
    </Modal>
  );
}
