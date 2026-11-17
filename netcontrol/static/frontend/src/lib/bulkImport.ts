/**
 * Bulk import (CSV / YAML / JSON) - the object types, request building and
 * report helpers the shared ImportDialog uses. The server side is
 * `netcontrol/bulk_import.py`; see docs/bulk-import.md.
 */
import type { Tone } from '@/lib/severity';

export type ImportType = 'hosts' | 'groups' | 'prefixes' | 'addresses' | 'vlans' | 'vrfs';
export type ImportFamily = 'inventory' | 'ipam';
export type ImportFormat = 'csv' | 'yaml' | 'json';
export type ImportMode = 'create' | 'update' | 'upsert';
export type ImportAction = 'create' | 'update' | 'skip' | 'error';
export type ImportStep = 'preview' | 'commit' | 'template';

export interface ImportTypeInfo {
  label: string;
  family: ImportFamily;
  /** The keys a row may be matched on, the first being the default. */
  matchKeys: readonly { key: string; label: string }[];
}

export const IMPORT_TYPES: Record<ImportType, ImportTypeInfo> = {
  hosts: {
    label: 'Hosts',
    family: 'inventory',
    matchKeys: [
      { key: 'hostname', label: 'Hostname' },
      { key: 'ip', label: 'IP address' },
    ],
  },
  groups: { label: 'Inventory groups', family: 'inventory', matchKeys: [{ key: 'path', label: 'Group path' }] },
  prefixes: { label: 'IPAM prefixes', family: 'ipam', matchKeys: [{ key: 'prefix', label: 'Prefix and VRF' }] },
  addresses: { label: 'IP addresses', family: 'ipam', matchKeys: [{ key: 'address', label: 'Address' }] },
  vlans: { label: 'VLANs', family: 'ipam', matchKeys: [{ key: 'vid', label: 'VLAN id and site' }] },
  vrfs: { label: 'VRFs', family: 'ipam', matchKeys: [{ key: 'name', label: 'Name' }] },
};

export const IMPORT_MODES: readonly { key: ImportMode; label: string; title: string }[] = [
  { key: 'create', label: 'Create', title: 'Add new objects; rows that match an existing one are skipped' },
  { key: 'update', label: 'Update', title: 'Change existing objects; rows that match none are errors' },
  { key: 'upsert', label: 'Create or update', title: 'Add new objects and change the ones that exist' },
];

/** The largest file the server takes (MAX_IMPORT_BYTES). */
export const MAX_IMPORT_BYTES = 1024 * 1024;

/** The API path (under /api) of one import step for a type. */
export function importPath(type: ImportType, step: ImportStep): string {
  return `/import/${IMPORT_TYPES[type].family}/${type}/${step}`;
}

/** The format a file name implies, or null when its extension says nothing. */
export function formatFromFileName(name: string): ImportFormat | null {
  const ext = name.toLowerCase().split('.').pop() ?? '';
  if (ext === 'csv' || ext === 'txt') return 'csv';
  if (ext === 'yaml' || ext === 'yml') return 'yaml';
  if (ext === 'json') return 'json';
  return null;
}

export interface ImportInput {
  file: File | null;
  text: string;
  format: ImportFormat;
  mode: ImportMode;
  matchKey: string;
  /** Commit only: all or nothing (default) or stop at the first failing row. */
  atomic?: boolean;
}

/** Why the input cannot be sent yet, or null when it can. */
export function inputProblem(input: Pick<ImportInput, 'file' | 'text'>): string | null {
  if (input.file) {
    return input.file.size > MAX_IMPORT_BYTES ? 'The file is larger than 1 MiB. Split it into smaller files.' : null;
  }
  if (!input.text.trim()) return 'Choose a file or paste the rows to import.';
  if (new Blob([input.text]).size > MAX_IMPORT_BYTES) return 'The pasted text is larger than 1 MiB.';
  return null;
}

/** The multipart body of a preview or commit request. */
export function buildImportForm(input: ImportInput): FormData {
  const form = new FormData();
  if (input.file) form.append('file', input.file, input.file.name);
  else form.append('text', input.text);
  form.append('format', input.format);
  form.append('mode', input.mode);
  form.append('match_key', input.matchKey);
  if (input.atomic !== undefined) form.append('atomic', input.atomic ? 'true' : 'false');
  return form;
}

export interface ImportFieldError {
  field: string;
  message: string;
}

export interface ImportRow {
  row: number;
  key: string;
  action: ImportAction;
  errors: ImportFieldError[];
  changes: Record<string, { before: string; after: string }>;
  warnings: string[];
}

export interface ImportReport {
  object_type: ImportType;
  format: ImportFormat;
  mode: ImportMode;
  match_key: string;
  columns: string[];
  ignored_columns: { column: string; reason: string }[];
  new_tags: string[];
  summary: Record<ImportAction | 'total', number>;
  rows: ImportRow[];
  committed: boolean;
  applied: number;
  message: string;
}

export const ACTION_LABEL: Record<ImportAction, string> = {
  create: 'Create',
  update: 'Update',
  skip: 'Skip',
  error: 'Error',
};

export function actionTone(action: ImportAction): Tone {
  switch (action) {
    case 'create':
      return 'success';
    case 'update':
      return 'info';
    case 'error':
      return 'danger';
    default:
      return 'neutral';
  }
}

function plural(n: number, word: string): string {
  return `${n.toLocaleString()} ${word}${n === 1 ? '' : 's'}`;
}

/** One line for the preview: what the import would do. */
export function summaryText(report: Pick<ImportReport, 'summary'>): string {
  const s = report.summary;
  const parts = [`${s.create.toLocaleString()} to create`, `${s.update.toLocaleString()} to update`];
  if (s.skip) parts.push(`${s.skip.toLocaleString()} unchanged or skipped`);
  if (s.error) parts.push(plural(s.error, 'row') + ' with errors');
  return `${plural(s.total, 'row')}: ${parts.join(', ')}.`;
}

/**
 * Whether the previewed import can be committed: something to write, and,
 * all or nothing, no row with errors.
 */
export function canCommit(report: Pick<ImportReport, 'summary'>, atomic: boolean): boolean {
  const s = report.summary;
  if (s.create + s.update === 0) return false;
  return !atomic || s.error === 0;
}

/** The rows a filter keeps: every row, or only those with that action. */
export function filterRows(rows: readonly ImportRow[], action: ImportAction | 'all'): ImportRow[] {
  return action === 'all' ? [...rows] : rows.filter((r) => r.action === action);
}

/** An update's changes as a list, in the order the server gave them. */
export function changeList(row: Pick<ImportRow, 'changes'>): { field: string; before: string; after: string }[] {
  return Object.entries(row.changes).map(([field, c]) => ({ field, before: c.before, after: c.after }));
}

/** A row's errors as one line: "field: message; message". */
export function errorText(row: Pick<ImportRow, 'errors'>): string {
  return row.errors.map((e) => (e.field ? `${e.field}: ${e.message}` : e.message)).join('; ');
}

/** The report a refused commit (422) carries in its body, if any. */
export function reportFromErrorBody(body: unknown): ImportReport | null {
  if (!body || typeof body !== 'object') return null;
  const rec = body as Partial<ImportReport>;
  return Array.isArray(rec.rows) && rec.summary && typeof rec.summary === 'object' ? (rec as ImportReport) : null;
}
