import { useId, useState } from 'react';

import {
  type CustomField,
  CustomDataError,
  type CustomFieldInput as FieldInput,
  type FieldType,
  type ObjectType,
  useCreateCustomField,
  useUpdateCustomField,
} from '@/api/customData';
import { Callout } from '@/components/Callout';
import { CustomFieldInput } from '@/components/CustomFieldsForm';
import { useDialogs } from '@/components/DialogProvider-context';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import {
  countObjects,
  FIELD_TYPE_LABELS,
  FIELD_TYPES,
  type FieldFormErrors,
  OBJECT_TYPE_LABELS,
  OBJECT_TYPES,
  parseChoices,
  suggestFieldKey,
  validateFieldForm,
} from '@/lib/customData';
import { parseBoundedInt } from '@/lib/numberInput';

import { CheckboxField, FormRow } from './FormFields';

type Field = keyof FieldFormErrors;

/** "groups", "hosts and groups", "hosts, groups and IPAM prefixes". */
function joinTypes(types: ObjectType[]): string {
  const names = types.map((t) => OBJECT_TYPE_LABELS[t].many);
  return names.length <= 1 ? (names[0] ?? '') : `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
}

/** The confirm text for a field update that removes object types holding values. */
function removalMessage(removed: ObjectType[], affected: number | null): string {
  const question = `Remove this field from ${joinTypes(removed)}?`;
  if (affected === null) return `${question} Their values for it are deleted.`;
  const who = removed.length === 1 ? countObjects(affected, removed[0]) : countObjects(affected);
  return `${question} ${who} lose${affected === 1 ? 's its' : ' their'} value.`;
}

/**
 * Creates a custom field (`field` null) or edits one. Key and type are set
 * on create and read-only afterwards.
 */
export function CustomFieldModal({ field, onClose }: { field: CustomField | null; onClose: () => void }) {
  const id = useId();
  const isCreate = field === null;
  const { confirm } = useDialogs();
  const create = useCreateCustomField();
  const update = useUpdateCustomField();

  const [label, setLabel] = useState(field?.label ?? '');
  const [key, setKey] = useState(field?.key ?? '');
  const [keyEdited, setKeyEdited] = useState(!isCreate);
  const [fieldType, setFieldType] = useState<FieldType>(field?.field_type ?? 'text');
  const [objectTypes, setObjectTypes] = useState<ObjectType[]>(field?.object_types ?? ['host']);
  const [choicesText, setChoicesText] = useState((field?.choices ?? []).join('\n'));
  const [defaultValue, setDefaultValue] = useState(field?.default_value ?? '');
  const [required, setRequired] = useState(field?.required ?? false);
  const [order, setOrder] = useState(String(field?.sort_order ?? 0));
  const [description, setDescription] = useState(field?.description ?? '');
  const [touched, setTouched] = useState<Partial<Record<Field, boolean>>>({});
  const [keyTaken, setKeyTaken] = useState<string | null>(null);
  const [failure, setFailure] = useState<string | null>(null);

  const effectiveKey = keyEdited ? key : suggestFieldKey(label);
  const input: FieldInput = {
    key: effectiveKey,
    label: label.trim(),
    field_type: fieldType,
    choices: fieldType === 'select' ? parseChoices(choicesText) : [],
    object_types: OBJECT_TYPES.filter((t) => objectTypes.includes(t)),
    required,
    default_value: defaultValue,
    description: description.trim(),
    sort_order: parseBoundedInt(order, -100000, 100000, 0),
  };
  const errors = validateFieldForm(input, isCreate);
  if (isCreate && keyTaken !== null && keyTaken === effectiveKey) {
    errors.key = `A field with the key "${effectiveKey}" already exists.`;
  }
  const shown = (name: Field) => (touched[name] ? errors[name] : undefined);
  const touch = (name: Field) => setTouched((t) => ({ ...t, [name]: true }));
  const busy = create.isPending || update.isPending;

  const save = async (confirmed = false): Promise<void> => {
    if (isCreate) {
      await create.mutateAsync(input);
      return;
    }
    const { key: _key, field_type: _type, ...data } = input;
    await update.mutateAsync({ id: field.id, data, confirm: confirmed });
  };

  const submit = async () => {
    setTouched({ label: true, key: true, object_types: true, choices: true, default_value: true });
    if (Object.keys(errors).length > 0) return;
    setFailure(null);
    try {
      await save();
      onClose();
    } catch (err) {
      if (err instanceof CustomDataError && err.status === 409 && isCreate) {
        setKeyTaken(effectiveKey);
        return;
      }
      if (err instanceof CustomDataError && err.status === 409 && field) {
        const removed = field.object_types.filter((t) => !input.object_types.includes(t));
        const agreed = await confirm({
          title: 'Remove field values',
          message: removalMessage(removed.length ? removed : field.object_types, err.affected),
          confirmLabel: 'Remove values',
        });
        if (!agreed) return;
        try {
          await save(true);
          onClose();
        } catch (retryErr) {
          setFailure((retryErr as Error).message);
        }
        return;
      }
      setFailure((err as Error).message);
    }
  };

  const toggleType = (type: ObjectType, on: boolean) => {
    setObjectTypes((prev) => (on ? [...prev, type] : prev.filter((t) => t !== type)));
    touch('object_types');
  };

  // The default uses the input for the chosen type; a yes/no default is a
  // choice so that "no default" stays possible.
  const defaultField =
    fieldType === 'boolean'
      ? { key: 'default', label: 'Default value', field_type: 'select' as const, choices: ['true', 'false'], required: false, description: '' }
      : {
          key: 'default',
          label: 'Default value',
          field_type: fieldType,
          choices: input.choices,
          required: false,
          description: 'Prefilled in the form of an object that has no value yet. Leave empty for none.',
        };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={isCreate ? 'New field' : `Edit field ${field.label}`}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={isCreate ? 'Create field' : 'Save field'}
          primaryBusy={busy}
          primaryBusyLabel="Saving…"
          onPrimary={() => void submit()}
        />
      }
    >
      {failure && (
        <Callout tone="danger" title="The field was not saved">
          {failure} Check the fields and try again.
        </Callout>
      )}

      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-label`}>
          Label
        </label>
        <input
          id={`${id}-label`}
          className="form-input"
          value={label}
          maxLength={100}
          autoFocus
          aria-invalid={!!shown('label')}
          aria-describedby={`${id}-label-error`}
          onChange={(e) => setLabel(e.target.value)}
          onBlur={() => touch('label')}
        />
        <FieldError id={`${id}-label-error`}>{shown('label')}</FieldError>
      </div>

      <FormRow>
        <div className="form-group" style={{ flex: '1 1 14rem' }}>
          <label className="form-label" htmlFor={`${id}-key`}>
            Key
          </label>
          <input
            id={`${id}-key`}
            className="form-input"
            style={{ fontFamily: 'var(--font-mono)' }}
            value={effectiveKey}
            readOnly={!isCreate}
            spellCheck={false}
            autoComplete="off"
            maxLength={50}
            aria-invalid={!!shown('key')}
            aria-describedby={`${id}-key-help ${id}-key-error`}
            onChange={(e) => {
              setKey(e.target.value);
              setKeyEdited(true);
            }}
            onBlur={() => touch('key')}
          />
          <div className="form-help" id={`${id}-key-help`}>
            {isCreate
              ? 'Used in the API and in filters (cf.<key>). Lowercase letters, digits and _. It cannot change later.'
              : 'The key cannot change after the field is created.'}
          </div>
          <FieldError id={`${id}-key-error`}>{shown('key')}</FieldError>
        </div>

        <div className="form-group" style={{ flex: '1 1 12rem' }}>
          <label className="form-label" htmlFor={`${id}-type`}>
            Type
          </label>
          <select
            id={`${id}-type`}
            className="form-select"
            value={fieldType}
            disabled={!isCreate}
            aria-describedby={isCreate ? undefined : `${id}-type-help`}
            onChange={(e) => {
              setFieldType(e.target.value as FieldType);
              setDefaultValue('');
            }}
          >
            {FIELD_TYPES.map((t) => (
              <option key={t} value={t}>
                {FIELD_TYPE_LABELS[t]}
              </option>
            ))}
          </select>
          {!isCreate && (
            <div className="form-help" id={`${id}-type-help`}>
              The type cannot change after the field is created.
            </div>
          )}
        </div>
      </FormRow>

      <fieldset className="form-group fieldset-plain" aria-describedby={`${id}-types-error`}>
        <legend className="form-label">Applies to</legend>
        <div className="form-check-row" style={{ marginBottom: 0 }}>
          {OBJECT_TYPES.map((type) => (
            <label key={type} className="form-check">
              <input
                type="checkbox"
                checked={objectTypes.includes(type)}
                onChange={(e) => toggleType(type, e.target.checked)}
              />
              <span>{OBJECT_TYPE_LABELS[type].title}</span>
            </label>
          ))}
        </div>
        {!isCreate && (
          <div className="form-help">Clearing a type deletes the values this field holds on objects of that type.</div>
        )}
        <FieldError id={`${id}-types-error`}>{shown('object_types')}</FieldError>
      </fieldset>

      {fieldType === 'select' && (
        <div className="form-group">
          <label className="form-label" htmlFor={`${id}-choices`}>
            Choices
          </label>
          <textarea
            id={`${id}-choices`}
            className="form-textarea"
            rows={4}
            value={choicesText}
            aria-invalid={!!shown('choices')}
            aria-describedby={`${id}-choices-help ${id}-choices-error`}
            onChange={(e) => setChoicesText(e.target.value)}
            onBlur={() => touch('choices')}
          />
          <div className="form-help" id={`${id}-choices-help`}>
            One per line. Removing a choice keeps the values already set until that object is next saved.
          </div>
          <FieldError id={`${id}-choices-error`}>{shown('choices')}</FieldError>
        </div>
      )}

      <div onBlur={() => touch('default_value')}>
        <CustomFieldInput
          field={defaultField}
          value={defaultValue}
          error={shown('default_value')}
          onChange={(v) => setDefaultValue(v === '' ? '' : String(v))}
        />
      </div>

      <FormRow>
        <div className="form-group" style={{ flex: '0 1 10rem' }}>
          <label className="form-label" htmlFor={`${id}-order`}>
            Order
          </label>
          <input
            id={`${id}-order`}
            className="form-input"
            type="number"
            step={1}
            value={order}
            aria-describedby={`${id}-order-help`}
            onChange={(e) => setOrder(e.target.value)}
          />
          <div className="form-help" id={`${id}-order-help`}>
            Lower numbers show first.
          </div>
        </div>
        <CheckboxField
          inRow
          label="Required"
          checked={required}
          onChange={setRequired}
          help={required ? 'Saving an object needs a value or a default. Existing objects stay as they are until then.' : undefined}
        />
      </FormRow>

      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-description`}>
          Help text (optional)
        </label>
        <textarea
          id={`${id}-description`}
          className="form-textarea"
          rows={2}
          value={description}
          maxLength={500}
          aria-describedby={`${id}-description-help`}
          onChange={(e) => setDescription(e.target.value)}
        />
        <div className="form-help" id={`${id}-description-help`}>
          Shown under the input.
        </div>
      </div>
    </Modal>
  );
}
