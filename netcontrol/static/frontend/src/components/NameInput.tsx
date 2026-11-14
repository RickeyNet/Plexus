import type { NameField } from '@/lib/useNameField';

import { FieldError } from './FieldError';

export interface NameInputProps {
  /** Prefix for the control ids (a `useId()` value). */
  id: string;
  label: string;
  field: NameField;
  max: number;
  help: string;
}

/** The name input of a create / edit dialog, bound to a `useNameField`. Takes focus on open. */
export function NameInput({ id, label, field, max, help }: NameInputProps) {
  return (
    <div className="form-group">
      <label className="form-label" htmlFor={`${id}-name`}>
        {label}
      </label>
      <input
        id={`${id}-name`}
        className="form-input"
        value={field.value}
        maxLength={max + 1}
        autoFocus
        aria-invalid={!!field.shownError}
        aria-describedby={`${id}-name-help ${id}-name-error`}
        onChange={(e) => field.setValue(e.target.value)}
        onBlur={field.touch}
      />
      <div className="form-help" id={`${id}-name-help`}>
        {help}
      </div>
      <FieldError id={`${id}-name-error`}>{field.shownError}</FieldError>
    </div>
  );
}
