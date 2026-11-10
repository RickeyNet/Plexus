import { type ReactNode, useId } from 'react';

/**
 * A wrapping row of fields. Children are `.form-group`s (TextField,
 * NumberField, a hand-written select) and `CheckboxField`s with `inRow`.
 */
export function FormRow({ children }: { children: ReactNode }) {
  return <div className="form-row">{children}</div>;
}

/** A wrapping row made only of checkboxes; spaced clear of the fields below. */
export function CheckboxRow({ children }: { children: ReactNode }) {
  return <div className="form-check-row">{children}</div>;
}

export function CheckboxField({
  label,
  checked,
  onChange,
  disabled,
  help,
  inRow = false,
}: {
  label: ReactNode;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  help?: ReactNode;
  /**
   * Set when the checkbox sits in a <FormRow> beside labelled inputs: it
   * reserves the label line so the box lines up with the inputs, not their
   * labels.
   */
  inRow?: boolean;
}) {
  const check = (
    <label className="form-check">
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>{label}</span>
    </label>
  );
  if (!inRow && !help) return check;
  return (
    <div className={`form-group${inRow ? ' form-check-field' : ''}`}>
      {inRow && (
        <span className="form-label" aria-hidden="true">
          &nbsp;
        </span>
      )}
      {check}
      {help && <div className="form-help">{help}</div>}
    </div>
  );
}

export function TextField({
  label,
  value,
  onChange,
  type = 'text',
  flex,
  placeholder,
  help,
  autoComplete,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  type?: string;
  flex?: string;
  placeholder?: string;
  help?: ReactNode;
  autoComplete?: string;
}) {
  const id = useId();
  return (
    <div className="form-group" style={flex ? { flex } : undefined}>
      <label className="form-label" htmlFor={id}>{label}</label>
      <input
        id={id}
        className="form-input"
        type={type}
        value={value}
        placeholder={placeholder}
        autoComplete={autoComplete}
        aria-describedby={help ? `${id}-help` : undefined}
        onChange={(e) => onChange(e.target.value)}
      />
      {help && <div className="form-help" id={`${id}-help`}>{help}</div>}
    </div>
  );
}

export function NumberField({
  label,
  value,
  onChange,
  min,
  max,
  step,
  flex = '0 1 140px',
  disabled,
  help,
}: {
  label: string;
  value: number;
  onChange: (v: number) => void;
  min?: number;
  max?: number;
  step?: number | string;
  flex?: string;
  disabled?: boolean;
  help?: ReactNode;
}) {
  const id = useId();
  return (
    <div className="form-group" style={{ flex }}>
      <label className="form-label" htmlFor={id}>{label}</label>
      <input
        id={id}
        type="number"
        className="form-input"
        min={min}
        max={max}
        step={step}
        disabled={disabled}
        value={value}
        aria-describedby={help ? `${id}-help` : undefined}
        onChange={(e) => onChange(Number(e.target.value))}
      />
      {help && <div className="form-help" id={`${id}-help`}>{help}</div>}
    </div>
  );
}
