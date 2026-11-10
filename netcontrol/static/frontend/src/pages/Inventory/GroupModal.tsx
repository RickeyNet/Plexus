import { FormEvent, useId, useMemo, useState } from 'react';

import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import {
  groupLabel,
  type InventoryGroupFull,
  useCreateInventoryGroup,
  useUpdateInventoryGroup,
} from '@/api/inventory';

import { descendantIds } from './helpers';

interface Props {
  group: InventoryGroupFull | null;
  isCreate: boolean;
  /** Every inventory group (tree ordered), for the Parent group select. */
  groups: InventoryGroupFull[];
  /** The parent a new group starts under (New Sub-group); null for top level. */
  defaultParentId?: number | null;
  onClose: () => void;
}

export function GroupModal({ group, isCreate, groups, defaultParentId = null, onClose }: Props) {
  const formId = useId();
  const create = useCreateInventoryGroup();
  const update = useUpdateInventoryGroup();
  const [name, setName] = useState(group?.name ?? '');
  const [description, setDescription] = useState(group?.description ?? '');
  const [parentId, setParentId] = useState<number | null>(
    group ? (group.parent_id ?? null) : defaultParentId,
  );
  const [nameError, setNameError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  // A group cannot be its own parent or move under one of its sub-groups.
  const parentChoices = useMemo(() => {
    if (!group) return groups;
    const excluded = descendantIds(groups, group.id);
    excluded.add(group.id);
    return groups.filter((g) => !excluded.has(g.id));
  }, [groups, group]);

  const isPending = create.isPending || update.isPending;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSaveError(null);
    const trimmedName = name.trim();
    if (!trimmedName) {
      setNameError('Group name is required.');
      return;
    }
    try {
      if (isCreate) {
        await create.mutateAsync({ name: trimmedName, description, parent_id: parentId });
      } else if (group) {
        await update.mutateAsync({
          id: group.id,
          name: trimmedName,
          description,
          parent_id: parentId,
        });
      }
      onClose();
    } catch (err) {
      setSaveError((err as Error).message);
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={isCreate ? 'Create Inventory Group' : 'Edit Inventory Group'}
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={isPending}>
            {isPending ? 'Saving…' : isCreate ? 'Create' : 'Save'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={submit}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-name`}>Group Name</label>
          <input
            id={`${formId}-name`}
            className="form-input"
            value={name}
            onChange={(e) => {
              setName(e.target.value);
              setNameError(null);
            }}
            required
            autoFocus
            aria-invalid={!!nameError}
          />
          <FieldError>{nameError}</FieldError>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="inventory-group-parent">Parent group</label>
          <select
            id="inventory-group-parent"
            className="form-select"
            value={parentId ?? ''}
            onChange={(e) => setParentId(e.target.value ? Number(e.target.value) : null)}
          >
            <option value="">None (top level)</option>
            {parentChoices.map((g) => (
              <option key={g.id} value={g.id}>
                {groupLabel(g)}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-description`}>Description</label>
          <textarea
            id={`${formId}-description`}
            className="form-textarea"
            value={description ?? ''}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>
      </form>
    </Modal>
  );
}
