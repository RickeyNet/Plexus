import type { Endpoint, EndpointInput, EndpointType, TraceStatus } from '@/api/dcim';

/** Display names of cable endpoint types. */
export const ENDPOINT_TYPE_LABELS: Record<string, string> = {
  interface: 'Interface',
  front_port: 'Front port',
  rear_port: 'Rear port',
  circuit_termination: 'Circuit termination',
  power_port: 'Power port',
  power_outlet: 'Power outlet',
  power_feed: 'Power feed',
};

export function endpointTypeLabel(type: string): string {
  return ENDPOINT_TYPE_LABELS[type] ?? type;
}

/** "device / port" for an endpoint; its type and id when nothing names it. */
export function endpointLabel(ep: Endpoint | null | undefined): string {
  if (!ep) return '-';
  if (ep.label) return ep.label;
  const name = ep.name || (ep.id != null ? `#${ep.id}` : '');
  const host = ep.host_name ?? '';
  return [host, name].filter(Boolean).join(' / ') || endpointTypeLabel(ep.type);
}

const TRACE_STATUS: Record<TraceStatus, string> = {
  complete: 'Complete path',
  dead_end: 'Ends at a port with no further cable',
  unconnected: 'No cable on this endpoint',
  missing: 'Ends at a record that no longer exists',
  ambiguous: 'Enters a multi-position rear port without a position',
  loop: 'The path loops back on itself',
  restricted: 'Continues through records outside your access',
};

export function traceStatusText(status: TraceStatus | string): string {
  return TRACE_STATUS[status as TraceStatus] ?? status;
}

/**
 * The rack units of a list such as `"1-3, 7"`: sorted, without repeats.
 * `null` when a part is not a unit or a range (low to high) of units.
 */
export function parseUnits(text: string): number[] | null {
  const units = new Set<number>();
  const parts = text
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean);
  if (parts.length === 0) return null;
  for (const part of parts) {
    const m = /^(\d+)(?:\s*-\s*(\d+))?$/.exec(part);
    if (!m) return null;
    const low = Number(m[1]);
    const high = m[2] === undefined ? low : Number(m[2]);
    if (low < 1 || high < low || high - low > 100) return null;
    for (let u = low; u <= high; u += 1) units.add(u);
  }
  return [...units].sort((a, b) => a - b);
}

/** Units as runs: `[1, 2, 3, 7]` is `"1-3, 7"`. */
export function formatUnits(units: readonly number[]): string {
  const sorted = [...new Set(units)].sort((a, b) => a - b);
  const runs: string[] = [];
  let start: number | null = null;
  let prev: number | null = null;
  for (const u of [...sorted, Number.NaN]) {
    if (prev !== null && u === prev + 1) {
      prev = u;
      continue;
    }
    if (start !== null && prev !== null) runs.push(start === prev ? `${start}` : `${start}-${prev}`);
    start = u;
    prev = u;
  }
  return runs.join(', ');
}

/** Watts as "850 W" or "3.7 kW". */
export function formatWatts(watts: number | null | undefined): string {
  if (watts === null || watts === undefined) return '-';
  if (Math.abs(watts) >= 1000) return `${(watts / 1000).toFixed(1)} kW`;
  return `${Math.round(watts)} W`;
}

/** Unit label of a block: "U7" or "U3-U4" (display order kept, lowest first). */
export function blockUnitsLabel(units: readonly number[]): string {
  if (units.length === 0) return '';
  const low = Math.min(...units);
  const high = Math.max(...units);
  return low === high ? `U${low}` : `U${low}-U${high}`;
}

/** One input of a DCIM record form. */
export interface FieldSpec {
  key: string;
  label: string;
  kind: 'text' | 'textarea' | 'number' | 'select' | 'ref' | 'checkbox' | 'tenant' | 'units';
  /** `select`: the choices (value = label unless given). `ref`: ids and labels. */
  options?: readonly (string | { value: string | number; label: string })[];
  required?: boolean;
  /** The value of a new record. */
  initial?: unknown;
  /** Shown on create only (a fixed parent such as the device). */
  createOnly?: boolean;
  help?: string;
  min?: number;
  max?: number;
}

/**
 * The value a field sends, or an error message. Empty optional numbers and
 * references send null.
 */
export function fieldValue(field: FieldSpec, raw: string | boolean): { value?: unknown; error?: string } {
  if (field.kind === 'checkbox') return { value: Boolean(raw) };
  const text = String(raw).trim();
  if (field.kind === 'units') {
    const units = parseUnits(text);
    return units ? { value: units } : { error: 'Enter units such as 1-3, 7.' };
  }
  if (field.kind === 'number' || field.kind === 'ref' || field.kind === 'tenant') {
    if (text === '') return field.required ? { error: `${field.label} is required.` } : { value: null };
    const n = Number(text);
    if (!Number.isFinite(n)) return { error: `${field.label} must be a number.` };
    if (field.min !== undefined && n < field.min) return { error: `${field.label} must be at least ${field.min}.` };
    if (field.max !== undefined && n > field.max) return { error: `${field.label} must be at most ${field.max}.` };
    return { value: n };
  }
  if (field.required && text === '') return { error: `${field.label} is required.` };
  return { value: text };
}

/** The trace a URL asks for (`?trace_type=&trace_id=` or `&trace_host=&trace_name=`). */
export function traceFromParams(params: URLSearchParams): EndpointInput | null {
  const type = params.get('trace_type') as EndpointType | null;
  if (!type) return null;
  if (type === 'interface') {
    const host = Number(params.get('trace_host'));
    const name = params.get('trace_name') ?? '';
    return host && name ? { type, host_id: host, name } : null;
  }
  const id = Number(params.get('trace_id'));
  return id ? { type, id } : null;
}

/** The link that opens the trace of an endpoint on the Cables tab. */
export function traceLink(ep: EndpointInput): string {
  const p = new URLSearchParams({ trace_type: ep.type });
  if (ep.type === 'interface') {
    p.set('trace_host', String(ep.host_id ?? ''));
    p.set('trace_name', ep.name ?? '');
  } else p.set('trace_id', String(ep.id ?? ''));
  return `/dcim/cables?${p.toString()}`;
}
