/**
 * Pure helpers of the Sync page: labels, job and connection drafts and
 * their checks, the mapping editor's JSON, run summaries and the rows of a
 * per-object diff. The server repeats every check.
 */
import type { Tone } from '@/lib/severity';

export type SyncKind = 'netbox' | 'nautobot' | 'servicenow';
export type SyncDirection = 'import' | 'export' | 'bidirectional';
export type SyncPolicy = 'source_wins' | 'plexus_wins' | 'skip_conflicts';
export type SyncObjectType =
  | 'sites'
  | 'manufacturers'
  | 'device_types'
  | 'vrfs'
  | 'vlans'
  | 'prefixes'
  | 'ip_addresses'
  | 'devices';
export type SyncAction = 'create' | 'update' | 'delete' | 'conflict';
export type SyncOutcome = 'planned' | 'applied' | 'failed' | 'skipped';

export const SYNC_NAME_MAX = 100;
export const HOST_GROUP_MAX = 200;
export const INTERVAL_MIN = 5;
export const INTERVAL_MAX = 7 * 24 * 60;
export const TIMEOUT_MIN = 5;
export const TIMEOUT_MAX = 300;

/** In the order a run handles them (dependencies first). */
export const OBJECT_TYPES: readonly SyncObjectType[] = [
  'sites',
  'manufacturers',
  'device_types',
  'vrfs',
  'vlans',
  'prefixes',
  'ip_addresses',
  'devices',
];

export const OBJECT_TYPE_LABEL: Record<SyncObjectType, string> = {
  sites: 'Sites',
  manufacturers: 'Manufacturers',
  device_types: 'Device types',
  vrfs: 'VRFs',
  vlans: 'VLANs',
  prefixes: 'Prefixes',
  ip_addresses: 'IP addresses',
  devices: 'Devices',
};

export const KIND_LABEL: Record<SyncKind, string> = {
  netbox: 'NetBox',
  nautobot: 'Nautobot',
  servicenow: 'ServiceNow CMDB',
};

export const AUTH_LABEL: Record<string, string> = {
  token: 'API token',
  basic: 'Basic (username and password)',
  oauth: 'OAuth client credentials',
};

export const DIRECTION_LABEL: Record<SyncDirection, string> = {
  import: 'Import into Plexus',
  export: 'Export from Plexus',
  bidirectional: 'Both ways',
};

export const DIRECTION_HELP: Record<SyncDirection, string> = {
  import: 'The remote system is the source of truth: Plexus records are created and updated to match it.',
  export: 'Plexus is the source of truth: the remote system is created and updated to match Plexus.',
  bidirectional:
    'Missing records are created on either side and empty fields filled; two different values are a conflict. Never deletes.',
};

export const POLICY_LABEL: Record<SyncPolicy, string> = {
  source_wins: 'Remote wins',
  plexus_wins: 'Plexus wins',
  skip_conflicts: 'Skip conflicts',
};

export const ACTION_LABEL: Record<SyncAction, string> = {
  create: 'Create',
  update: 'Update',
  delete: 'Delete',
  conflict: 'Conflict',
};

export const OUTCOME_TONE: Record<SyncOutcome, Tone> = {
  planned: 'info',
  applied: 'success',
  failed: 'danger',
  skipped: 'neutral',
};

export const ACTION_TONE: Record<SyncAction, Tone> = {
  create: 'success',
  update: 'info',
  delete: 'danger',
  conflict: 'warning',
};

/** "Every 15 minutes", "Every 2 hours", "Manual only". */
export function describeSchedule(minutes: number): string {
  if (!minutes) return 'Manual only';
  if (minutes % 1440 === 0) return minutes === 1440 ? 'Daily' : `Every ${minutes / 1440} days`;
  if (minutes % 60 === 0) return minutes === 60 ? 'Hourly' : `Every ${minutes / 60} hours`;
  return `Every ${minutes} minutes`;
}

/** Where an entry writes: Plexus, or the connection kind's name. */
export function targetLabel(target: 'plexus' | 'remote', kind: SyncKind | undefined): string {
  return target === 'plexus' ? 'Plexus' : kind ? KIND_LABEL[kind] : 'Remote';
}

// ── Job drafts ──────────────────────────────────────────────────────────────

export interface JobDraft {
  name: string;
  connection_id: number | null;
  object_types: SyncObjectType[];
  direction: SyncDirection;
  conflict_policy: SyncPolicy;
  delete_missing: boolean;
  mappingsText: string;
  host_group: string;
  interval: string;
  enabled: boolean;
  description: string;
}

export type JobErrors = Partial<Record<'name' | 'connection_id' | 'object_types' | 'mappings' | 'host_group' | 'interval', string>>;

export function emptyJobDraft(connectionId: number | null): JobDraft {
  return {
    name: '',
    connection_id: connectionId,
    object_types: ['sites', 'devices'],
    direction: 'import',
    conflict_policy: 'skip_conflicts',
    delete_missing: false,
    mappingsText: '',
    host_group: 'Synced',
    interval: '0',
    enabled: true,
    description: '',
  };
}

export function jobDraftOf(job: {
  name: string;
  connection_id: number;
  object_types: SyncObjectType[];
  direction: SyncDirection;
  conflict_policy: SyncPolicy;
  delete_missing: boolean;
  mappings: object;
  options: { host_group?: string };
  interval_minutes: number;
  enabled: boolean;
  description: string;
}): JobDraft {
  return {
    name: job.name,
    connection_id: job.connection_id,
    object_types: [...job.object_types],
    direction: job.direction,
    conflict_policy: job.conflict_policy,
    delete_missing: job.delete_missing,
    mappingsText: formatMappings(job.mappings),
    host_group: job.options.host_group ?? 'Synced',
    interval: String(job.interval_minutes),
    enabled: job.enabled,
    description: job.description,
  };
}

/** The mapping editor's text: '' for no mapping, else indented JSON. */
export function formatMappings(mappings: object | null | undefined): string {
  return mappings && Object.keys(mappings).length ? JSON.stringify(mappings, null, 2) : '';
}

/**
 * The mapping text as an object (`{}` for blank), or the reason it is not
 * one: JSON keyed by object type, each an object of field -> path / true /
 * false.
 */
export function parseMappings(text: string): { value: Record<string, Record<string, unknown>> } | { error: string } {
  if (!text.trim()) return { value: {} };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { error: 'Not valid JSON.' };
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { error: 'Give an object keyed by object type, such as {"devices": {"role": true}}.' };
  }
  for (const [type, fields] of Object.entries(parsed)) {
    if (!(OBJECT_TYPES as readonly string[]).includes(type)) return { error: `Unknown object type "${type}".` };
    if (!fields || typeof fields !== 'object' || Array.isArray(fields)) {
      return { error: `The mapping of ${type} must be an object.` };
    }
  }
  return { value: parsed as Record<string, Record<string, unknown>> };
}

export function validateJob(draft: JobDraft): JobErrors {
  const errors: JobErrors = {};
  const name = draft.name.trim();
  if (!name) errors.name = 'Enter a name.';
  else if (name.length > SYNC_NAME_MAX) errors.name = `At most ${SYNC_NAME_MAX} characters.`;
  if (draft.connection_id === null) errors.connection_id = 'Pick a connection.';
  if (!draft.object_types.length) errors.object_types = 'Pick at least one object type.';
  const mapped = parseMappings(draft.mappingsText);
  if ('error' in mapped) errors.mappings = mapped.error;
  if (draft.host_group.length > HOST_GROUP_MAX) errors.host_group = `At most ${HOST_GROUP_MAX} characters.`;
  const text = draft.interval.trim();
  const minutes = Number(text);
  if (!/^\d+$/.test(text) || (minutes !== 0 && (minutes < INTERVAL_MIN || minutes > INTERVAL_MAX))) {
    errors.interval = `0 (manual only) or ${INTERVAL_MIN} to ${INTERVAL_MAX} minutes.`;
  }
  return errors;
}

/** The request body of a valid draft. */
export function toJobInput(draft: JobDraft) {
  const mapped = parseMappings(draft.mappingsText);
  return {
    name: draft.name.trim(),
    connection_id: draft.connection_id ?? 0,
    object_types: OBJECT_TYPES.filter((t) => draft.object_types.includes(t)),
    direction: draft.direction,
    conflict_policy: draft.conflict_policy,
    delete_missing: draft.direction !== 'bidirectional' && draft.delete_missing,
    mappings: 'value' in mapped ? mapped.value : {},
    host_group: draft.host_group.trim() || 'Synced',
    interval_minutes: Number(draft.interval.trim() || 0),
    enabled: draft.enabled,
    description: draft.description.trim(),
  };
}

/** Whether a real run of the job would write into Plexus. */
export function writesPlexus(direction: SyncDirection): boolean {
  return direction !== 'export';
}

// ── Connection drafts ───────────────────────────────────────────────────────

export type ConnectionErrors = Partial<Record<'name' | 'base_url' | 'credential_id' | 'timeout_seconds', string>>;

export function validateConnection(draft: {
  name: string;
  base_url: string;
  credential_id: number | null;
  timeout_seconds: number;
}): ConnectionErrors {
  const errors: ConnectionErrors = {};
  const name = draft.name.trim();
  if (!name) errors.name = 'Enter a name.';
  else if (name.length > SYNC_NAME_MAX) errors.name = `At most ${SYNC_NAME_MAX} characters.`;
  const url = draft.base_url.trim();
  if (!url) errors.base_url = 'Enter the address, such as https://netbox.example.com.';
  else if (/^http:\/\//i.test(url)) errors.base_url = 'Use https: the address receives the credential.';
  else if (/[?#@]/.test(url)) errors.base_url = 'Give the address only: no user, query or fragment.';
  if (draft.credential_id === null) errors.credential_id = 'Pick the service credential holding the secret.';
  if (!Number.isInteger(draft.timeout_seconds) || draft.timeout_seconds < TIMEOUT_MIN || draft.timeout_seconds > TIMEOUT_MAX) {
    errors.timeout_seconds = `${TIMEOUT_MIN} to ${TIMEOUT_MAX} seconds.`;
  }
  return errors;
}

// ── Runs ────────────────────────────────────────────────────────────────────

export interface RunTotals {
  create: number;
  update: number;
  delete: number;
  conflict: number;
  unchanged: number;
  applied: number;
  failed: number;
  skipped: number;
  errors: number;
}

/** A run's counts over every object type (types that failed to load count in `errors`). */
export function runTotals(summary: Record<string, { error?: string } & Partial<Record<keyof RunTotals, number>>>): RunTotals {
  const totals: RunTotals = { create: 0, update: 0, delete: 0, conflict: 0, unchanged: 0, applied: 0, failed: 0, skipped: 0, errors: 0 };
  for (const s of Object.values(summary)) {
    if (s.error) {
      totals.errors += 1;
      continue;
    }
    for (const k of ['create', 'update', 'delete', 'conflict', 'unchanged', 'applied', 'failed', 'skipped'] as const) {
      totals[k] += s[k] ?? 0;
    }
  }
  return totals;
}

/** "3 create · 1 update" for the non-zero planned actions; "No changes" otherwise. */
export function describeTotals(t: RunTotals): string {
  const parts = (['create', 'update', 'delete', 'conflict'] as const).filter((k) => t[k] > 0).map((k) => `${t[k]} ${k}`);
  return parts.length ? parts.join(' · ') : 'No changes';
}

export interface DiffRow {
  field: string;
  left: string;
  right: string;
}

/**
 * The rows of an entry's per-field diff and the column titles: before /
 * after on the target for a create, update or delete; Plexus / remote for
 * a conflict.
 */
export function diffRows(entry: {
  action: SyncAction;
  changes: Record<string, { before?: string; after?: string; plexus?: string; remote?: string }>;
}): { columns: [string, string]; rows: DiffRow[] } {
  const conflict = entry.action === 'conflict';
  const rows = Object.entries(entry.changes).map(([field, c]) => ({
    field,
    left: (conflict ? c.plexus : c.before) ?? '',
    right: (conflict ? c.remote : c.after) ?? '',
  }));
  return { columns: conflict ? ['Plexus', 'Remote'] : ['Before', 'After'], rows };
}

/** A field name as words: `ip_address` -> "ip address". */
export function fieldLabel(field: string): string {
  return field.replace(/_/g, ' ');
}
