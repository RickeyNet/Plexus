import { useId } from 'react';

import { type CustomField, type CustomValue, type ObjectType, useCustomFields } from '@/api/customData';
import { applicableFields, type FormValues } from '@/lib/customData';

import { FieldError } from './FieldError';

export interface CustomFieldInputProps {
  /** The definition: label, type, choices, required and description are used. */
  field: Pick<CustomField, 'key' | 'label' | 'field_type' | 'choices' | 'required' | 'description'>;
  value: CustomValue | '';
  onChange: (value: CustomValue | '') => void;
  error?: string;
  disabled?: boolean;
}

/**
 * One labelled input for a custom field, by type: text, number, checkbox,
 * date, URL, or a select with an empty option. A stored select value that is
 * no longer a choice stays listed, marked "(removed)".
 */
export function CustomFieldInput({ field, value, onChange, error, disabled }: CustomFieldInputProps) {
  const id = useId();
  const helpId = field.description ? `${id}-help` : '';
  const errorId = error ? `${id}-error` : '';
  const describedBy = [helpId, errorId].filter(Boolean).join(' ') || undefined;
  const required = field.required ? (
    <span className="form-required" aria-hidden="true">
      {' '}
      *
    </span>
  ) : null;
  const text = value === '' ? '' : String(value);

  if (field.field_type === 'boolean') {
    return (
      <div className="form-group">
        <label className="form-check">
          <input
            type="checkbox"
            checked={value === true || value === 'true'}
            disabled={disabled}
            aria-invalid={!!error}
            aria-describedby={describedBy}
            onChange={(e) => onChange(e.target.checked)}
          />
          <span>
            {field.label}
            {required}
          </span>
        </label>
        {field.description && (
          <div className="form-help" id={helpId}>
            {field.description}
          </div>
        )}
        <FieldError id={errorId || undefined}>{error}</FieldError>
      </div>
    );
  }

  const common = {
    id,
    disabled,
    'aria-invalid': !!error,
    'aria-required': field.required || undefined,
    'aria-describedby': describedBy,
  };

  let control;
  if (field.field_type === 'select') {
    const removed = text !== '' && !field.choices.includes(text);
    control = (
      <select {...common} className="form-select" value={text} onChange={(e) => onChange(e.target.value)}>
        <option value="">Not set</option>
        {field.choices.map((choice) => (
          <option key={choice} value={choice}>
            {choice}
          </option>
        ))}
        {removed && <option value={text}>{text} (removed)</option>}
      </select>
    );
  } else {
    const inputType = { text: 'text', number: 'number', date: 'date', url: 'url' }[field.field_type];
    control = (
      <input
        {...common}
        className="form-input"
        type={inputType}
        step={field.field_type === 'number' ? 'any' : undefined}
        inputMode={field.field_type === 'number' ? 'decimal' : undefined}
        maxLength={field.field_type === 'text' ? 1000 : undefined}
        placeholder={field.field_type === 'url' ? 'https://example.com' : undefined}
        value={text}
        onChange={(e) => onChange(e.target.value)}
      />
    );
  }

  return (
    <div className="form-group">
      <label className="form-label" htmlFor={id}>
        {field.label}
        {required}
      </label>
      {control}
      {field.description && (
        <div className="form-help" id={helpId}>
          {field.description}
        </div>
      )}
      <FieldError id={errorId || undefined}>{error}</FieldError>
    </div>
  );
}

export interface CustomFieldsFormProps {
  objectType: ObjectType;
  values: FormValues;
  onChange: (values: FormValues) => void;
  /** Messages by field key, shown under each field. */
  errors?: Record<string, string>;
  disabled?: boolean;
}

/**
 * One input per custom field that applies to `objectType`, in display order.
 * Renders nothing when no field applies.
 */
export function CustomFieldsForm({ objectType, values, onChange, errors = {}, disabled }: CustomFieldsFormProps) {
  const fieldsQ = useCustomFields(objectType);
  const fields = applicableFields(fieldsQ.data ?? [], objectType);
  if (fields.length === 0) return null;
  return (
    <div className="custom-fields-form">
      {fields.map((field) => (
        <CustomFieldInput
          key={field.id}
          field={field}
          value={values[field.key] ?? ''}
          error={errors[field.key]}
          disabled={disabled}
          onChange={(next) => onChange({ ...values, [field.key]: next })}
        />
      ))}
    </div>
  );
}
