import { useState } from 'react';

import { useBulkTagHosts } from '@/api/customData';
import { Callout } from '@/components/Callout';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { TagPicker } from '@/components/TagPicker';

interface Props {
  hostIds: number[];
  onClose: () => void;
}

/** Adds and removes tags on the selected hosts in one request. */
export function BulkTagModal({ hostIds, onClose }: Props) {
  const bulk = useBulkTagHosts();
  const [addIds, setAddIds] = useState<number[]>([]);
  const [removeIds, setRemoveIds] = useState<number[]>([]);
  const [error, setError] = useState<string | null>(null);
  const count = hostIds.length;
  const hosts = `${count} host${count === 1 ? '' : 's'}`;
  const each = count === 1 ? 'the host' : `each of the ${hosts}`;
  const overlap = addIds.some((id) => removeIds.includes(id));

  const apply = () => {
    setError(null);
    bulk.mutate(
      { hostIds, addTagIds: addIds, removeTagIds: removeIds },
      {
        onSuccess: onClose,
        onError: (err) => setError(`The tags were not changed: ${err.message} Try again.`),
      },
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={`Tag ${hosts}`}
      size="small"
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel="Apply tags"
          primaryBusy={bulk.isPending}
          primaryBusyLabel="Applying…"
          primaryDisabled={(addIds.length === 0 && removeIds.length === 0) || overlap}
          onPrimary={apply}
        />
      }
    >
      {error && <Callout tone="danger">{error}</Callout>}
      {overlap && <Callout tone="warning">A tag cannot be both added and removed. Take it out of one list.</Callout>}
      <TagPicker
        label="Add tags"
        value={addIds}
        onChange={setAddIds}
        canCreate
        help={`Added to ${each}; tags already there stay.`}
      />
      <TagPicker
        label="Remove tags"
        value={removeIds}
        onChange={setRemoveIds}
        canCreate={false}
        help={`Taken off ${each} where present.`}
      />
    </Modal>
  );
}
