import { useId, useState } from 'react';

import { useBulkEditHosts } from '@/api/deviceModel';
import { Callout } from '@/components/Callout';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import {
  bulkChoiceToSelect,
  type BulkEditForm,
  bulkEditSet,
  EMPTY_BULK_EDIT,
  selectToBulkChoice,
} from '@/lib/deviceModel';

import { DeviceModelFields } from './DeviceModelFields';

interface Props {
  hostIds: number[];
  onClose: () => void;
}

/**
 * Sets the device type, role, lifecycle status, site and rack / room on the
 * selected hosts in one request. Every value starts at "Leave unchanged" and
 * only the changed ones are sent.
 */
export function BulkEditModal({ hostIds, onClose }: Props) {
  const id = useId();
  const bulk = useBulkEditHosts();
  const [form, setForm] = useState<BulkEditForm>(EMPTY_BULK_EDIT);
  const [error, setError] = useState<string | null>(null);
  const count = hostIds.length;
  const hosts = `${count} host${count === 1 ? '' : 's'}`;
  const set = bulkEditSet(form);
  const changes = Object.keys(set).length;

  const apply = () => {
    setError(null);
    bulk.mutate(
      { hostIds, set },
      {
        onSuccess: onClose,
        onError: (err) => setError(`The hosts were not changed: ${err.message} Check the values and try again.`),
      },
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={`Edit ${hosts}`}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={changes === 0 ? 'Apply changes' : `Apply ${changes} change${changes === 1 ? '' : 's'}`}
          primaryBusy={bulk.isPending}
          primaryBusyLabel="Applying…"
          primaryDisabled={changes === 0}
          onPrimary={apply}
        />
      }
    >
      {error && <Callout tone="danger">{error}</Callout>}
      <p className="form-help" style={{ marginTop: 0 }}>
        Choose a value for each thing to change on {count === 1 ? 'the host' : `all ${hosts}`}. Values left at
        &quot;Leave unchanged&quot; stay as each host has them. Setting a device type or role stops discovery from
        changing it.
      </p>
      <DeviceModelFields
        idPrefix={id}
        allowKeep
        ids={{
          device_type_id: bulkChoiceToSelect(form.device_type_id),
          role_id: bulkChoiceToSelect(form.role_id),
          lifecycle_status_id: bulkChoiceToSelect(form.lifecycle_status_id),
          site_id: bulkChoiceToSelect(form.site_id),
        }}
        onIdChange={(key, value) => setForm((prev) => ({ ...prev, [key]: selectToBulkChoice(value) }))}
        location={form.location_detail}
        onLocationChange={(value) => setForm((prev) => ({ ...prev, location_detail: value }))}
      />
    </Modal>
  );
}
