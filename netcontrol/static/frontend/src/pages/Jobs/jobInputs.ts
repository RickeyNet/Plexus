/**
 * Typed job inputs: the run dialog's values and checks, and the schema
 * editor's rows. Mirrors the server rules in netcontrol/job_inputs.py so a
 * field is flagged on blur; the server re-checks every value on launch.
 */
import type { JobInputField, JobInputType } from '@/api/jobs';

export const JOB_INPUT_TYPES: { value: JobInputType; label: string }[] = [
  { value: 'string', label: 'Text (one line)' },
  { value: 'text', label: 'Text (multi-line)' },
  { value: 'integer', label: 'Whole number' },
  { value: 'boolean', label: 'Yes / no' },
  { value: 'choice', label: 'Choice' },
  { value: 'multichoice', label: 'Multiple choice' },
  { value: 'list', label: 'List (comma-separated)' },
  { value: 'ip', label: 'IP address' },
  { value: 'cidr', label: 'Prefix (CIDR)' },
  { value: 'host', label: 'Inventory host' },
  { value: 'group', label: 'Inventory group' },
  { value: 'secret', label: 'Secret variable' },
];

export const STRING_MAX = 1000;
export const TEXT_MAX = 20000;
const FIELD_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const SECRET_NAME_RE = /^[A-Za-z_][A-Za-z0-9_-]{0,63}$/;
const SECRET_REF_RE = /\{\{ {0,8}secret\.[^}\s]{1,128} {0,8}\}\}/;
const BOUNDED: JobInputType[] = ['integer', 'string', 'text', 'multichoice', 'list'];
const CHOICES: JobInputType[] = ['choice', 'multichoice'];
const PATTERNED: JobInputType[] = ['string', 'text'];

/** A form value: text for most types, a flag for boolean, a list for multichoice. */
export type InputValue = string | boolean | string[];
export type InputValues = Record<string, InputValue>;

export function isBounded(type: JobInputType): boolean {
  return BOUNDED.includes(type);
}
export function hasChoices(type: JobInputType): boolean {
  return CHOICES.includes(type);
}
export function hasPattern(type: JobInputType): boolean {
  return PATTERNED.includes(type);
}

// ── Format checks ──────────────────────────────────────────────────────────

export function isIpv4(text: string): boolean {
  const parts = text.split('.');
  return (
    parts.length === 4 &&
    parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255 && (p === '0' || !p.startsWith('0')))
  );
}

export function isIpv6(text: string): boolean {
  if (!text.includes(':') || !/^[0-9A-Fa-f:.]+$/.test(text)) return false;
  try {
    // The URL parser validates IPv6 literals (and normalizes them).
    return new URL(`http://[${text}]/`).hostname.length > 2;
  } catch {
    return false;
  }
}

export function isIpAddress(text: string): boolean {
  return isIpv4(text) || isIpv6(text);
}

export function isCidr(text: string): boolean {
  const slash = text.indexOf('/');
  if (slash < 0 || slash !== text.lastIndexOf('/')) return false;
  const addr = text.slice(0, slash);
  const len = text.slice(slash + 1);
  if (!/^\d{1,3}$/.test(len)) return false;
  if (isIpv4(addr)) return Number(len) <= 32;
  if (isIpv6(addr)) return Number(len) <= 128;
  return false;
}

/** `{{secret.NAME}}` or `secret.NAME` reduced to `NAME` (as the server does). */
export function normalizeSecretName(raw: string): string {
  let name = raw.trim();
  if (name.startsWith('{{') && name.endsWith('}}')) name = name.slice(2, -2).trim();
  if (name.startsWith('secret.')) name = name.slice('secret.'.length);
  return name.trim();
}

function splitList(raw: InputValue): string[] {
  const parts = Array.isArray(raw) ? raw : String(raw).split(',');
  const out: string[] = [];
  for (const p of parts) {
    const t = String(p).trim();
    if (t && !out.includes(t)) out.push(t);
  }
  return out;
}

function isEmpty(value: InputValue | undefined): boolean {
  if (value === undefined) return true;
  if (Array.isArray(value)) return value.length === 0;
  if (typeof value === 'boolean') return false;
  return value.trim() === '';
}

function boundsError(field: JobInputField, size: number, unit: string): string | null {
  if (field.min != null && size < field.min) return `${field.label} must be at least ${field.min}${unit}.`;
  if (field.max != null && size > field.max) return `${field.label} must be at most ${field.max}${unit}.`;
  return null;
}

// ── Run dialog values ──────────────────────────────────────────────────────

/** The form's starting values: each field's default, or empty. */
export function seedInputValues(schema: JobInputField[]): InputValues {
  const values: InputValues = {};
  for (const f of schema) {
    const d = f.default;
    if (f.type === 'boolean') values[f.name] = d === true;
    else if (f.type === 'multichoice') values[f.name] = Array.isArray(d) ? d.map(String) : [];
    else if (Array.isArray(d)) values[f.name] = d.join(', ');
    else values[f.name] = d == null ? '' : String(d);
  }
  return values;
}

/** The message for one field's value, or null when it is fine. */
export function validateInputValue(field: JobInputField, value: InputValue | undefined): string | null {
  const label = field.label || field.name;
  if (isEmpty(value)) {
    const hasDefault = field.default != null && field.default !== '' && !(Array.isArray(field.default) && field.default.length === 0);
    return field.required && !hasDefault ? `${label} is required.` : null;
  }
  if (field.type === 'boolean') return null;
  if (field.type === 'multichoice' || field.type === 'list') {
    const items = splitList(value as InputValue);
    if (field.type === 'multichoice') {
      const bad = items.find((i) => !(field.choices ?? []).includes(i));
      if (bad) return `${label}: '${bad}' is not one of the choices.`;
    } else if (items.some((i) => SECRET_REF_RE.test(i))) {
      return `${label}: secret references are only allowed in secret fields.`;
    }
    return boundsError({ ...field, label }, items.length, ' item(s)');
  }
  const raw = String(value);
  const text = field.type === 'text' ? raw : raw.trim();
  if (field.type !== 'secret' && SECRET_REF_RE.test(text)) {
    return `${label}: secret references are only allowed in secret fields.`;
  }
  switch (field.type) {
    case 'integer': {
      if (!/^-?\d+$/.test(text)) return `${label} must be a whole number.`;
      return boundsError({ ...field, label }, Number(text), '');
    }
    case 'string':
    case 'text': {
      const limit = field.type === 'string' ? STRING_MAX : TEXT_MAX;
      if (text.length > limit) return `${label} must be at most ${limit} characters.`;
      const bounds = boundsError({ ...field, label }, text.length, ' character(s)');
      if (bounds) return bounds;
      if (field.regex) {
        try {
          if (!new RegExp(`^(?:${field.regex})$`).test(text)) return `${label} does not match the required format.`;
        } catch {
          // A pattern JavaScript cannot compile is left to the server.
        }
      }
      return null;
    }
    case 'choice':
      return (field.choices ?? []).includes(text) ? null : `${label} must be one of: ${(field.choices ?? []).join(', ')}.`;
    case 'ip':
      return isIpAddress(text) ? null : `${label} must be an IP address, for example 192.0.2.10.`;
    case 'cidr':
      return isCidr(text) ? null : `${label} must be a prefix in CIDR form, for example 192.0.2.0/24.`;
    case 'host':
    case 'group':
      return /^[1-9]\d*$/.test(text) ? null : `${label} must be selected.`;
    case 'secret':
      return SECRET_NAME_RE.test(normalizeSecretName(text)) ? null : `${label} must name a secret variable.`;
    default:
      return null;
  }
}

/** One message per bad field, keyed by field name. */
export function validateInputs(schema: JobInputField[], values: InputValues): Record<string, string> {
  const errors: Record<string, string> = {};
  for (const f of schema) {
    const msg = validateInputValue(f, values[f.name]);
    if (msg) errors[f.name] = msg;
  }
  return errors;
}

/** The `inputs` body for launch: typed values, empty fields left out (the server applies defaults). */
export function buildInputsPayload(schema: JobInputField[], values: InputValues): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of schema) {
    const v = values[f.name];
    if (f.type === 'boolean') {
      out[f.name] = v === true;
      continue;
    }
    if (isEmpty(v)) continue;
    if (f.type === 'integer' || f.type === 'host' || f.type === 'group') out[f.name] = Number(String(v).trim());
    else if (f.type === 'multichoice' || f.type === 'list') out[f.name] = splitList(v as InputValue);
    else if (f.type === 'secret') out[f.name] = normalizeSecretName(String(v));
    else out[f.name] = v;
  }
  return out;
}

/**
 * A job record's stored inputs (`jobs.parameters` JSON) as one line for the
 * output window: hosts and groups by name, secrets by reference only.
 */
export function formatJobInputs(raw: string | null | undefined): string {
  if (!raw) return '';
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return '';
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return '';
  const show = (v: unknown): string => {
    if (Array.isArray(v)) return v.map(show).join(', ');
    if (v && typeof v === 'object') {
      const o = v as { hostname?: unknown; name?: unknown; id?: unknown };
      return String(o.hostname || o.name || o.id || '');
    }
    const text = String(v);
    const secret = /^\{\{\s*secret\.([^}\s]+)\s*\}\}$/.exec(text);
    return secret ? `secret ${secret[1]}` : text;
  };
  return Object.entries(parsed as Record<string, unknown>)
    .map(([k, v]) => `${k}=${show(v)}`)
    .join('; ');
}

// ── Schema editor rows ─────────────────────────────────────────────────────

/** One field definition as the editor holds it: every attribute as text. */
export interface SchemaRow {
  name: string;
  type: JobInputType;
  label: string;
  help: string;
  required: boolean;
  default: string;
  choices: string;
  min: string;
  max: string;
  regex: string;
}

export function emptyRow(): SchemaRow {
  return { name: '', type: 'string', label: '', help: '', required: false, default: '', choices: '', min: '', max: '', regex: '' };
}

export function rowFromField(f: JobInputField): SchemaRow {
  const d = f.default;
  return {
    name: f.name,
    type: f.type,
    label: f.label ?? '',
    help: f.help ?? '',
    required: Boolean(f.required),
    default: d == null ? '' : Array.isArray(d) ? d.join(', ') : String(d),
    choices: (f.choices ?? []).join(', '),
    min: f.min == null ? '' : String(f.min),
    max: f.max == null ? '' : String(f.max),
    regex: f.regex ?? '',
  };
}

/** The field definition the server receives (it normalizes and re-validates it). */
export function fieldFromRow(row: SchemaRow): JobInputField {
  const field: JobInputField = {
    name: row.name.trim(),
    type: row.type,
    label: row.label.trim() || row.name.trim(),
    help: row.help.trim(),
    required: row.required,
  };
  const dflt = row.default.trim();
  if (dflt && row.type !== 'host' && row.type !== 'group') {
    if (row.type === 'boolean') field.default = dflt === 'true';
    else if (row.type === 'integer' && /^-?\d+$/.test(dflt)) field.default = Number(dflt);
    else if (row.type === 'multichoice') field.default = splitList(dflt);
    else field.default = dflt;
  }
  if (hasChoices(row.type)) field.choices = splitList(row.choices);
  if (isBounded(row.type)) {
    if (/^-?\d+$/.test(row.min.trim())) field.min = Number(row.min.trim());
    if (/^-?\d+$/.test(row.max.trim())) field.max = Number(row.max.trim());
  }
  if (hasPattern(row.type) && row.regex.trim()) field.regex = row.regex.trim();
  return field;
}

/** Editor checks, keyed `"<index>.<attr>"` like the server's 422 `fields`. */
export function validateSchemaRows(rows: SchemaRow[]): Record<string, string> {
  const errors: Record<string, string> = {};
  const seen = new Set<string>();
  rows.forEach((row, i) => {
    const name = row.name.trim();
    if (!FIELD_NAME_RE.test(name)) {
      errors[`${i}.name`] = 'Use letters, digits and _, starting with a letter or _.';
    } else if (seen.has(name)) {
      errors[`${i}.name`] = `The name '${name}' is used twice.`;
    }
    seen.add(name);
    if (hasChoices(row.type) && splitList(row.choices).length === 0) {
      errors[`${i}.choices`] = 'Add at least one choice.';
    }
    if (isBounded(row.type)) {
      const min = row.min.trim();
      const max = row.max.trim();
      if (min && !/^-?\d+$/.test(min)) errors[`${i}.min`] = 'Must be a whole number.';
      if (max && !/^-?\d+$/.test(max)) errors[`${i}.max`] = 'Must be a whole number.';
      if (/^-?\d+$/.test(min) && /^-?\d+$/.test(max) && Number(min) > Number(max)) {
        errors[`${i}.max`] = 'Max must not be less than min.';
      }
    }
    if (hasPattern(row.type) && row.regex.trim()) {
      try {
        new RegExp(row.regex.trim());
      } catch {
        errors[`${i}.regex`] = 'Not a valid regular expression.';
      }
    }
    const dflt = row.default.trim();
    if (dflt && !errors[`${i}.name`] && (row.type === 'host' || row.type === 'group')) {
      errors[`${i}.default`] = 'Host and group fields cannot have a default.';
    } else if (dflt && !errors[`${i}.name`] && row.type !== 'boolean') {
      const field = fieldFromRow(row);
      const msg = validateInputValue({ ...field, required: false }, row.type === 'multichoice' ? splitList(dflt) : dflt);
      if (msg) errors[`${i}.default`] = `Default: ${msg}`;
    }
  });
  return errors;
}
