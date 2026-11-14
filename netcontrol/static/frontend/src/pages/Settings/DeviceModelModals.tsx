import { useId, useState } from 'react';

import {
  type DeviceRole,
  type DeviceType,
  type HostStatus,
  type Manufacturer,
  useCreateDeviceRole,
  useCreateDeviceType,
  useCreateHostStatus,
  useCreateManufacturer,
  useManufacturers,
  useUpdateDeviceRole,
  useUpdateDeviceType,
  useUpdateHostStatus,
  useUpdateManufacturer,
} from '@/api/deviceModel';
import { DescriptionInput, SaveFailure } from '@/components/CatalogueParts';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { NameInput } from '@/components/NameInput';
import { TagChip } from '@/components/TagChips';
import { TagColorPicker } from '@/components/TagColorPicker';
import { idToSelect, selectToId } from '@/lib/deviceModel';
import { parseBoundedInt } from '@/lib/numberInput';
import { runSave } from '@/lib/recordSave';
import { useNameField } from '@/lib/useNameField';

const MANUFACTURER_NAME_MAX = 100;
const MODEL_MAX = 100;
const PART_NUMBER_MAX = 100;
const ROLE_NAME_MAX = 50;
const U_HEIGHT_MAX = 100;

// ── Manufacturer ───────────────────────────────────────────────────────────

export function ManufacturerModal({ manufacturer, onClose }: { manufacturer: Manufacturer | null; onClose: () => void }) {
  const id = useId();
  const create = useCreateManufacturer();
  const update = useUpdateManufacturer();
  const name = useNameField(manufacturer?.name ?? '', MANUFACTURER_NAME_MAX, 'Name', (n) => `A manufacturer named "${n}" already exists.`);
  const [description, setDescription] = useState(manufacturer?.description ?? '');
  const [failure, setFailure] = useState<string | null>(null);

  const submit = () => {
    name.touch();
    if (name.error) return;
    const data = { name: name.trimmed, description: description.trim() };
    void runSave(
      () => (manufacturer ? update.mutateAsync({ id: manufacturer.id, data }) : create.mutateAsync(data)),
      name,
      setFailure,
      onClose,
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="small"
      title={manufacturer ? `Edit manufacturer ${manufacturer.name}` : 'New manufacturer'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={manufacturer ? 'Save manufacturer' : 'Create manufacturer'}
          primaryBusy={create.isPending || update.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what="manufacturer" message={failure} />
      <NameInput
        id={id}
        label="Name"
        field={name}
        max={MANUFACTURER_NAME_MAX}
        help={`Up to ${MANUFACTURER_NAME_MAX} characters. Names are unique, ignoring case.`}
      />
      <DescriptionInput id={id} value={description} onChange={setDescription} />
    </Modal>
  );
}

// ── Device type ────────────────────────────────────────────────────────────

export function DeviceTypeModal({ deviceType, onClose }: { deviceType: DeviceType | null; onClose: () => void }) {
  const id = useId();
  const manufacturersQ = useManufacturers();
  const create = useCreateDeviceType();
  const update = useUpdateDeviceType();
  const [manufacturerId, setManufacturerId] = useState<number | null>(
    deviceType?.manufacturer_id ?? null,
  );
  const [manufacturerTouched, setManufacturerTouched] = useState(false);
  const model = useNameField(deviceType?.model ?? '', MODEL_MAX, 'Model', (m) => `This manufacturer already has a device type "${m}".`);
  const [partNumber, setPartNumber] = useState(deviceType?.part_number ?? '');
  const [uHeight, setUHeight] = useState(String(deviceType?.u_height ?? 0));
  const [description, setDescription] = useState(deviceType?.description ?? '');
  const [failure, setFailure] = useState<string | null>(null);

  const manufacturers = manufacturersQ.data ?? [];
  // Preselect the only manufacturer there is.
  const chosenManufacturer = manufacturerId ?? (manufacturers.length === 1 ? manufacturers[0].id : null);
  const manufacturerError = chosenManufacturer === null ? 'Choose a manufacturer.' : undefined;
  const uHeightText = uHeight.trim();
  const uHeightError =
    uHeightText !== '' && !/^\d+$/.test(uHeightText)
      ? `U height must be a whole number from 0 to ${U_HEIGHT_MAX}.`
      : Number(uHeightText) > U_HEIGHT_MAX
        ? `U height must be ${U_HEIGHT_MAX} or less.`
        : undefined;

  const submit = () => {
    model.touch();
    setManufacturerTouched(true);
    if (model.error || manufacturerError || uHeightError || chosenManufacturer === null) return;
    const data = {
      manufacturer_id: chosenManufacturer,
      model: model.trimmed,
      part_number: partNumber.trim(),
      u_height: parseBoundedInt(uHeight, 0, U_HEIGHT_MAX, 0),
      description: description.trim(),
    };
    void runSave(
      () => (deviceType ? update.mutateAsync({ id: deviceType.id, data }) : create.mutateAsync(data)),
      model,
      setFailure,
      onClose,
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="small"
      title={deviceType ? `Edit device type ${deviceType.model}` : 'New device type'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={deviceType ? 'Save device type' : 'Create device type'}
          primaryBusy={create.isPending || update.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what="device type" message={failure} />
      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-manufacturer`}>
          Manufacturer
        </label>
        <select
          id={`${id}-manufacturer`}
          className="form-select"
          value={idToSelect(chosenManufacturer)}
          aria-invalid={manufacturerTouched && !!manufacturerError}
          onChange={(e) => setManufacturerId(selectToId(e.target.value))}
          onBlur={() => setManufacturerTouched(true)}
        >
          <option value="">Choose a manufacturer</option>
          {manufacturers.map((m) => (
            <option key={m.id} value={m.id}>
              {m.name}
            </option>
          ))}
        </select>
        <FieldError>{manufacturerTouched ? manufacturerError : undefined}</FieldError>
      </div>
      <NameInput
        id={id}
        label="Model"
        field={model}
        max={MODEL_MAX}
        help={`Up to ${MODEL_MAX} characters, unique per manufacturer ignoring case, such as C9300-48P.`}
      />
      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-part`}>
          Part number (optional)
        </label>
        <input
          id={`${id}-part`}
          className="form-input"
          value={partNumber}
          maxLength={PART_NUMBER_MAX}
          spellCheck={false}
          onChange={(e) => setPartNumber(e.target.value)}
        />
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-u`}>
          U height
        </label>
        <input
          id={`${id}-u`}
          className="form-input"
          type="number"
          inputMode="numeric"
          min={0}
          max={U_HEIGHT_MAX}
          step={1}
          value={uHeight}
          aria-invalid={!!uHeightError}
          aria-describedby={`${id}-u-help`}
          onChange={(e) => setUHeight(e.target.value)}
          style={{ maxWidth: '8rem' }}
        />
        <div className="form-help" id={`${id}-u-help`}>
          Rack units the device takes, 0 to {U_HEIGHT_MAX}. Use 0 for devices that are not rack mounted.
        </div>
        <FieldError>{uHeightError}</FieldError>
      </div>
      <DescriptionInput id={id} value={description} onChange={setDescription} />
    </Modal>
  );
}

// ── Role and lifecycle status ──────────────────────────────────────────────

type ColorRecordKind = 'role' | 'status';

const COLOR_RECORD_TEXT: Record<ColorRecordKind, { noun: string; title: string }> = {
  role: { noun: 'role', title: 'role' },
  status: { noun: 'lifecycle status', title: 'status' },
};

/**
 * Creates or edits a role (`kind` "role") or a lifecycle status (`kind`
 * "status", which adds the Default checkbox). The default status cannot be
 * unticked here; making another status the default moves the flag.
 */
export function ColorRecordModal({
  kind,
  record,
  onClose,
}: {
  kind: ColorRecordKind;
  record: DeviceRole | HostStatus | null;
  onClose: () => void;
}) {
  const id = useId();
  const createRole = useCreateDeviceRole();
  const updateRole = useUpdateDeviceRole();
  const createStatus = useCreateHostStatus();
  const updateStatus = useUpdateHostStatus();
  const text = COLOR_RECORD_TEXT[kind];
  const name = useNameField(record?.name ?? '', ROLE_NAME_MAX, 'Name', (n) => `A ${text.noun} named "${n}" already exists.`);
  const [color, setColor] = useState<string>(record?.color ?? 'gray');
  const [description, setDescription] = useState(record?.description ?? '');
  const wasDefault = !!record && 'is_default' in record && record.is_default;
  const [isDefault, setIsDefault] = useState(wasDefault);
  const [failure, setFailure] = useState<string | null>(null);
  const busy = createRole.isPending || updateRole.isPending || createStatus.isPending || updateStatus.isPending;

  const submit = () => {
    name.touch();
    if (name.error) return;
    const data = { name: name.trimmed, color, description: description.trim() };
    const save = (): Promise<unknown> => {
      if (kind === 'role') {
        return record ? updateRole.mutateAsync({ id: record.id, data }) : createRole.mutateAsync(data);
      }
      const statusData = { ...data, is_default: isDefault };
      return record ? updateStatus.mutateAsync({ id: record.id, data: statusData }) : createStatus.mutateAsync(statusData);
    };
    void runSave(save, name, setFailure, onClose);
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="small"
      title={record ? `Edit ${text.noun} ${record.name}` : `New ${text.noun}`}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={record ? `Save ${text.title}` : `Create ${text.title}`}
          primaryBusy={busy}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what={text.noun} message={failure} />
      <NameInput
        id={id}
        label="Name"
        field={name}
        max={ROLE_NAME_MAX}
        help={`Up to ${ROLE_NAME_MAX} characters. Names are unique, ignoring case.`}
      />
      <TagColorPicker value={color} onChange={setColor} />
      <DescriptionInput id={id} value={description} onChange={setDescription} />
      {kind === 'status' && (
        <div className="form-group">
          <label className="form-check">
            <input
              type="checkbox"
              checked={isDefault}
              disabled={wasDefault}
              aria-describedby={`${id}-default-help`}
              onChange={(e) => setIsDefault(e.target.checked)}
            />
            Default
          </label>
          <div className="form-help" id={`${id}-default-help`}>
            {wasDefault
              ? 'This is the default status. To change that, edit another status and make it the default.'
              : 'New hosts get the default status. Making this the default takes the flag off the current one.'}
          </div>
        </div>
      )}
      <div className="form-group">
        <span className="form-label">Preview</span>
        <div>
          <TagChip color={color}>{name.trimmed || 'Name'}</TagChip>
        </div>
      </div>
    </Modal>
  );
}
