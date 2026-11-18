import { useCallback } from 'react';

import { useAuthStatus } from '@/api/auth';
import type { DeviceType } from '@/api/deviceModel';
import { Modal } from '@/components/Modal';
import { COMPONENT_TYPES, componentTypeLabel } from '@/lib/componentTemplates';

import { useRecordOptions } from '../Dcim/hooks';
import { RecordSection, Val } from '../Dcim/RecordSection';

/**
 * The component templates of one device type: the interfaces, console and
 * power ports, front and rear ports and module bays every device of the
 * type has. A device gets the missing ones as DCIM records when it is given
 * the type, or from its page's "Create components from device type".
 */
export function ComponentTemplatesModal({ deviceType, onClose }: { deviceType: DeviceType; onClose: () => void }) {
  const isAdmin = useAuthStatus().data?.role === 'admin';
  const rearLabel = useCallback(
    (r: Record<string, unknown>) =>
      r.device_type_id === deviceType.id && r.component_type === 'rear_port' ? `${String(r.name)} (${String(r.positions)})` : '',
    [deviceType.id],
  );
  const rears = useRecordOptions('component_template', rearLabel).filter((o) => o.label !== '');
  return (
    <Modal isOpen onClose={onClose} size="large" title={`Components of ${deviceType.manufacturer} ${deviceType.model}`}>
      <RecordSection
        kind="component_template"
        title="Component templates"
        what="component template"
        filters={{ device_type_id: deviceType.id }}
        canWrite={isAdmin}
        emptyText="No component templates yet. Add the ports and bays every device of this type has."
        fields={[
          {
            key: 'device_type_id',
            label: 'Device type',
            kind: 'ref',
            options: [{ value: deviceType.id, label: `${deviceType.manufacturer} ${deviceType.model}` }],
            initial: deviceType.id,
            required: true,
            createOnly: true,
          },
          {
            key: 'component_type',
            label: 'Component',
            kind: 'select',
            options: COMPONENT_TYPES.map((t) => ({ value: t, label: componentTypeLabel(t) })),
            initial: 'interface',
            required: true,
            createOnly: true,
          },
          { key: 'name', label: 'Name', kind: 'text', required: true },
          {
            key: 'type',
            label: 'Type',
            kind: 'text',
            help: 'An interface type such as 1000base-t; a connector for a console, front or rear port (rj-45, lc...). Empty for power ports and module bays.',
          },
          { key: 'positions', label: 'Positions (rear port)', kind: 'number', initial: 1, min: 1, max: 1024, required: true },
          { key: 'rear_port_template_id', label: 'Rear port (front port)', kind: 'ref', options: rears },
          { key: 'rear_port_position', label: 'Rear port position (front port)', kind: 'number', initial: 1, min: 1, max: 1024, required: true },
          { key: 'maximum_draw', label: 'Maximum draw, W (power port)', kind: 'number', min: 1 },
          { key: 'allocated_draw', label: 'Allocated draw, W (power port)', kind: 'number', min: 1 },
          { key: 'description', label: 'Description', kind: 'text' },
        ]}
        columns={[
          { label: 'Component', render: (r) => componentTypeLabel(r.component_type) },
          { label: 'Name', render: (r) => String(r.name) },
          { label: 'Type', render: (r) => <Val value={r.type} /> },
          {
            label: 'Details',
            render: (r) => {
              if (r.component_type === 'rear_port') return `${String(r.positions)} positions`;
              if (r.component_type === 'front_port') return `${String(r.rear_port_template_name)} : ${String(r.rear_port_position)}`;
              if (r.component_type === 'power_port' && r.maximum_draw) return `${String(r.maximum_draw)} W max`;
              return <Val value={r.description} />;
            },
          },
        ]}
      />
    </Modal>
  );
}
