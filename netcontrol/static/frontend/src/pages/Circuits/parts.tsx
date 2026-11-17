import type { ReactNode } from 'react';

import { Badge } from '@/components/Badge';
import { FieldError } from '@/components/FieldError';
import { circuitStatusLabel, circuitStatusTone } from '@/lib/circuits';

/** Pieces the circuits tabs and dialogs share. */

export function CircuitStatusBadge({ status }: { status: string }) {
  return (
    <Badge size="sm" tone={circuitStatusTone(status)}>
      {circuitStatusLabel(status)}
    </Badge>
  );
}

/** A labelled text input (or textarea) with its error under it. */
export function TextField({
  id,
  label,
  value,
  onChange,
  error,
  max,
  placeholder,
  help,
  multiline,
  autoFocus,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  error?: string;
  max: number;
  placeholder?: string;
  help?: ReactNode;
  multiline?: boolean;
  autoFocus?: boolean;
}) {
  const props = {
    id,
    className: 'form-input',
    value,
    maxLength: max,
    placeholder,
    autoFocus,
    'aria-invalid': !!error,
    'aria-describedby': error ? `${id}-error` : undefined,
  };
  return (
    <div className="form-group">
      <label className="form-label" htmlFor={id}>
        {label}
      </label>
      {multiline ? (
        <textarea {...props} className="form-textarea" rows={3} onChange={(e) => onChange(e.target.value)} />
      ) : (
        <input {...props} onChange={(e) => onChange(e.target.value)} />
      )}
      {help && <div className="form-help">{help}</div>}
      <FieldError id={`${id}-error`}>{error}</FieldError>
    </div>
  );
}

/** A labelled `<select>` of records by id ('' = none). */
export function IdSelect({
  id,
  label,
  value,
  onChange,
  options,
  none,
  error,
  disabled,
}: {
  id: string;
  label: string;
  value: number | null;
  onChange: (v: number | null) => void;
  options: { id: number; label: string }[];
  /** The label of the empty choice. */
  none: string;
  error?: string;
  disabled?: boolean;
}) {
  return (
    <div className="form-group">
      <label className="form-label" htmlFor={id}>
        {label}
      </label>
      <select
        id={id}
        className="form-select"
        value={value === null ? '' : String(value)}
        disabled={disabled}
        aria-invalid={!!error}
        aria-describedby={error ? `${id}-error` : undefined}
        onChange={(e) => onChange(e.target.value === '' ? null : Number(e.target.value))}
      >
        <option value="">{none}</option>
        {options.map((o) => (
          <option key={o.id} value={o.id}>
            {o.label}
          </option>
        ))}
      </select>
      <FieldError id={`${id}-error`}>{error}</FieldError>
    </div>
  );
}

/** A label / value row of a detail panel. */
export function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '9rem minmax(0, 1fr)', gap: '0.5rem', fontSize: '0.92em' }}>
      <div className="text-muted">{label}</div>
      <div style={{ wordBreak: 'break-word' }}>{children}</div>
    </div>
  );
}
