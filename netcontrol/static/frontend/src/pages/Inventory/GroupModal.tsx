import { FormEvent, useState } from 'react';

import { Modal } from '@/components/Modal';
import {
  type InventoryGroupFull,
  useCreateInventoryGroup,
  useUpdateInventoryGroup,
} from '@/api/inventory';

interface Props {
  group: InventoryGroupFull | null;
  isCreate: boolean;
  onClose: () => void;
}

export function GroupModal({ group, isCreate, onClose }: Props) {
  const create = useCreateInventoryGroup();
  const update = useUpdateInventoryGroup();
  const [name, setName] = useState(group?.name ?? '');
  const [description, setDescription] = useState(group?.description ?? '');

  const isPending = create.isPending || update.isPending;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const trimmedName = name.trim();
    if (!trimmedName) {
      alert('Group name is required.');
      return;
    }
    try {
      if (isCreate) {
        await create.mutateAsync({ name: trimmedName, description });
      } else if (group) {
        await update.mutateAsync({
          id: group.id,
          name: trimmedName,
          description,
        });
      }
      onClose();
    } catch (err) {
      alert((err as Error).message);
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={isCreate ? 'Create Inventory Group' : 'Edit Inventory Group'}
    >
      <form onSubmit={submit}>
        <div className="form-group">
          <label className="form-label">Group Name</label>
          <input
            className="form-input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            autoFocus
          />
        </div>
        <div className="form-group">
          <label className="form-label">Description</label>
          <textarea
            className="form-textarea"
            value={description ?? ''}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>
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
          <button type="submit" className="btn btn-primary" disabled={isPending}>
            {isPending ? 'Saving…' : isCreate ? 'Create' : 'Save'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
