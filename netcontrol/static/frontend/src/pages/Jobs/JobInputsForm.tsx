import { useId, type ReactNode } from 'react';

import { CustomFieldInput, type CustomFieldInputProps } from '@/components/CustomFieldsForm';
import { FieldError } from '@/components/FieldError';
import type { InventoryGroupFull } from '@/api/inventory';
import type { JobInputField } from '@/api/jobs';

import type { InputValue, InputValues } from './jobInputs';

interface Props {
  schema: JobInputField[];
  values: InputValues;
  /** Messages by field name, shown under each field. */
  errors: Record<string, string>;
  onChange: (name: string, value: InputValue) => void;
  onBlur: (name: string) => void;
  /** Inventory for host and group pickers. */
  groups: InventoryGroupFull[] | undefined;
  /** Secret variable names; undefined when the user cannot list them (a name is typed instead). */
  secretNames: string[] | undefined;
  disabled?: boolean;
}

const PLACEHOLDERS: Partial<Record<JobInputField['type'], string>> = {
  ip: '192.0.2.10',
  cidr: '192.0.2.0/24',
  list: 'item1, item2',
};

/**
 * The run dialog's typed inputs, one labelled control per schema field.
 * Simple types reuse the custom-field input; text, multiple choice and the
 * host, group and secret pickers are rendered here with the same markup.
 */
export function JobInputsForm({ schema, values, errors, onChange, onBlur, groups, secretNames, disabled }: Props) {
  if (schema.length === 0) return null;
  return (
    <div>
      {schema.map((f) => (
        <JobInputControl
          key={f.name}
          field={f}
          value={values[f.name]}
          error={errors[f.name]}
          onChange={(v) => onChange(f.name, v)}
          onBlur={() => onBlur(f.name)}
          groups={groups}
          secretNames={secretNames}
          disabled={disabled}
        />
      ))}
    </div>
  );
}

interface ControlProps {
  field: JobInputField;
  value: InputValue | undefined;
  error?: string;
  onChange: (value: InputValue) => void;
  onBlur: () => void;
  groups: InventoryGroupFull[] | undefined;
  secretNames: string[] | undefined;
  disabled?: boolean;
}

function asCustomField(field: JobInputField, secretNames: string[] | undefined): CustomFieldInputProps['field'] {
  const base = { key: field.name, label: field.label || field.name, required: Boolean(field.required), description: field.help ?? '', choices: [] as string[] };
  switch (field.type) {
    case 'integer':
      return { ...base, field_type: 'number' };
    case 'boolean':
      return { ...base, field_type: 'boolean' };
    case 'choice':
      return { ...base, field_type: 'select', choices: field.choices ?? [] };
    case 'secret':
      return secretNames ? { ...base, field_type: 'select', choices: secretNames } : { ...base, field_type: 'text' };
    default:
      return { ...base, field_type: 'text' };
  }
}

function JobInputControl({ field, value, error, onChange, onBlur, groups, secretNames, disabled }: ControlProps) {
  const id = useId();
  const label = field.label || field.name;
  const helpId = field.help ? `${id}-help` : '';
  const errorId = error ? `${id}-error` : '';
  const describedBy = [helpId, errorId].filter(Boolean).join(' ') || undefined;

  if (field.type !== 'text' && field.type !== 'multichoice' && field.type !== 'host' && field.type !== 'group') {
    return (
      <CustomFieldInput
        field={asCustomField(field, secretNames)}
        value={typeof value === 'boolean' || typeof value === 'string' ? value : ''}
        onChange={(v) => onChange(typeof v === 'boolean' ? v : String(v))}
        onBlur={onBlur}
        error={error}
        disabled={disabled}
        placeholder={PLACEHOLDERS[field.type]}
      />
    );
  }

  const required = field.required ? <span className="form-required" aria-hidden="true"> *</span> : null;
  const help = field.help ? <div className="form-help" id={helpId}>{field.help}</div> : null;
  const common = {
    disabled,
    onBlur,
    'aria-invalid': !!error,
    'aria-required': field.required || undefined,
    'aria-describedby': describedBy,
  };
  let control: ReactNode;

  if (field.type === 'multichoice') {
    const selected = Array.isArray(value) ? value : [];
    return (
      <div className="form-group">
        <span className="form-label" id={`${id}-label`}>{label}{required}</span>
        <div role="group" aria-labelledby={`${id}-label`} aria-describedby={describedBy}>
          {(field.choices ?? []).map((choice) => (
            <label key={choice} className="form-check">
              <input
                type="checkbox"
                checked={selected.includes(choice)}
                disabled={disabled}
                onBlur={onBlur}
                onChange={(e) =>
                  onChange(e.target.checked ? [...selected, choice] : selected.filter((c) => c !== choice))
                }
              />
              <span>{choice}</span>
            </label>
          ))}
        </div>
        {help}
        <FieldError id={errorId || undefined}>{error}</FieldError>
      </div>
    );
  }

  const text = typeof value === 'string' ? value : '';
  if (field.type === 'text') {
    control = (
      <textarea {...common} id={id} className="form-input" rows={4} value={text} onChange={(e) => onChange(e.target.value)} />
    );
  } else if (field.type === 'group') {
    control = (
      <select {...common} id={id} className="form-select" value={text} onChange={(e) => onChange(e.target.value)}>
        <option value="">Select a group…</option>
        {(groups ?? []).map((g) => (
          <option key={g.id} value={g.id}>{g.path || g.name}</option>
        ))}
      </select>
    );
  } else {
    control = (
      <select {...common} id={id} className="form-select" value={text} onChange={(e) => onChange(e.target.value)}>
        <option value="">Select a host…</option>
        {(groups ?? []).map((g) => (
          <optgroup key={g.id} label={g.path || g.name}>
            {(g.hosts ?? []).map((h) => (
              <option key={h.id} value={h.id}>{h.hostname} ({h.ip_address})</option>
            ))}
          </optgroup>
        ))}
      </select>
    );
  }

  return (
    <div className="form-group">
      <label className="form-label" htmlFor={id}>{label}{required}</label>
      {control}
      {help}
      <FieldError id={errorId || undefined}>{error}</FieldError>
    </div>
  );
}
