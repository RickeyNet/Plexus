import type { ReactNode } from 'react';

import { useAutonomousSystems } from '@/api/routing';
import { Badge } from '@/components/Badge';
import { FieldError } from '@/components/FieldError';
import {
  complianceStateHelp,
  complianceStateLabel,
  complianceStateTone,
  formatAsn,
  statusLabel,
  statusTone,
} from '@/lib/routing';

import { useHostOptions } from './routingHooks';

/** Pieces the Routing page's tabs, its dialogs and the device page share. */

export function RoutingStatusBadge({ status }: { status: string }) {
  return (
    <Badge size="sm" tone={statusTone(status)}>
      {statusLabel(status)}
    </Badge>
  );
}

export function ComplianceBadge({ state }: { state: string }) {
  return (
    <Badge size="sm" tone={complianceStateTone(state)} title={complianceStateHelp(state)}>
      {complianceStateLabel(state)}
    </Badge>
  );
}

/** A search box above a list; the value is deferred so typing stays smooth. */
export function SearchBox({ value, onChange, label, placeholder }: { value: string; onChange: (v: string) => void; label: string; placeholder: string }) {
  return (
    <input
      type="search"
      className="form-input form-input-sm"
      aria-label={label}
      placeholder={placeholder}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      style={{ width: 240, maxWidth: '100%' }}
    />
  );
}

/** A labelled form field with its error under it. */
export function Field({
  id,
  label,
  error,
  help,
  children,
}: {
  id: string;
  label: string;
  error?: string;
  help?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="form-group">
      <label className="form-label" htmlFor={id}>
        {label}
      </label>
      {children}
      {help && <div className="form-help">{help}</div>}
      <FieldError id={`${id}-error`}>{error}</FieldError>
    </div>
  );
}

export function HostSelect({
  id,
  value,
  onChange,
  allowNone,
  noneLabel = 'None',
  invalid,
}: {
  id: string;
  value: number | null;
  onChange: (v: number | null) => void;
  allowNone?: boolean;
  noneLabel?: string;
  invalid?: boolean;
}) {
  const { options, query } = useHostOptions();
  return (
    <select
      id={id}
      className="form-select"
      value={value ?? ''}
      aria-invalid={invalid}
      aria-describedby={`${id}-error`}
      disabled={query.isPending}
      onChange={(e) => onChange(e.target.value ? Number(e.target.value) : null)}
    >
      <option value="">{query.isPending ? 'Loading devices…' : allowNone ? noneLabel : 'Choose a device'}</option>
      {options.map((o) => (
        <option key={o.id} value={o.id}>
          {o.name}
        </option>
      ))}
    </select>
  );
}

export function AsSelect({
  id,
  value,
  onChange,
  allowNone,
  invalid,
}: {
  id: string;
  value: number | null;
  onChange: (v: number | null) => void;
  allowNone?: boolean;
  invalid?: boolean;
}) {
  const q = useAutonomousSystems();
  return (
    <select
      id={id}
      className="form-select"
      value={value ?? ''}
      aria-invalid={invalid}
      aria-describedby={`${id}-error`}
      disabled={q.isPending}
      onChange={(e) => onChange(e.target.value ? Number(e.target.value) : null)}
    >
      <option value="">{q.isPending ? 'Loading…' : allowNone ? 'None' : 'Choose an AS'}</option>
      {(q.data ?? []).map((a) => (
        <option key={a.id} value={a.id}>
          {formatAsn(a.asn)}
          {a.description ? ` · ${a.description}` : ''}
        </option>
      ))}
    </select>
  );
}
