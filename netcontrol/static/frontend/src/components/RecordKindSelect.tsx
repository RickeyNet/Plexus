import { type DcimKind, type DcimRecord, useDcimList } from '@/api/dcim';
import { idToSelect, selectToId } from '@/lib/deviceModel';

import { FieldError } from './FieldError';

export interface RecordKindSelectProps {
  /** The select's id; the help and error lines are `${id}-help` / `${id}-error`. */
  id: string;
  /** The record kind offered (a namespace, a VLAN group...). */
  kind: DcimKind;
  value: number | null;
  onChange: (id: number | null) => void;
  label: string;
  /** The text of the "none" choice; without it a record must be chosen. */
  noneLabel?: string;
  /** How a record reads in the list (default: its name). */
  labelOf?: (row: DcimRecord) => string;
  help?: string;
  error?: string;
}

/** A picker of one record of `kind`, as the shared record store lists them. */
export function RecordKindSelect({ id, kind, value, onChange, label, noneLabel, labelOf, help, error }: RecordKindSelectProps) {
  const q = useDcimList(kind);
  const rows = q.data ?? [];
  const known = value === null || rows.some((r) => r.id === value);
  const name = labelOf ?? ((r: DcimRecord) => String(r.name ?? r.id));
  return (
    <div className="form-group">
      <label className="form-label" htmlFor={id}>
        {label}
        {noneLabel ? ' (optional)' : ''}
      </label>
      <select
        id={id}
        className="form-select"
        value={idToSelect(value)}
        disabled={q.isError}
        aria-invalid={!!error}
        aria-describedby={`${id}-help ${id}-error`}
        onChange={(e) => onChange(selectToId(e.target.value))}
      >
        {(noneLabel || value === null) && <option value="">{noneLabel ?? 'Choose…'}</option>}
        {!known && <option value={idToSelect(value)}>{q.isLoading ? 'Loading…' : `#${value}`}</option>}
        {rows.map((r) => (
          <option key={r.id} value={r.id}>
            {name(r)}
          </option>
        ))}
      </select>
      {help && (
        <div className="form-help" id={`${id}-help`}>
          {help}
        </div>
      )}
      <FieldError id={`${id}-error`}>{error}</FieldError>
    </div>
  );
}
