/**
 * Sync framework under /api/sync: connections to NetBox, Nautobot and
 * ServiceNow (admin only to change), sync jobs (direction, conflict policy,
 * object types, field mappings, schedule), runs and their per-object
 * entries. Failures throw a `CustomDataError`: a 422 carries per-field
 * `fields`, a 409 a taken name, a connection used by jobs or a job already
 * running.
 */
import { useMutation, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query';

import type { SyncAction, SyncDirection, SyncKind, SyncObjectType, SyncOutcome, SyncPolicy } from '@/lib/sync';

import { queryString } from './client';
import { detailRequest, listOf } from './customData';

// ── Types ──────────────────────────────────────────────────────────────────

interface Stamps {
  created_by: string;
  created_at: string;
  updated_at: string;
  updated_by: string;
}

export interface SyncConnection extends Stamps {
  id: number;
  name: string;
  kind: SyncKind;
  base_url: string;
  auth_type: 'token' | 'basic' | 'oauth';
  credential_id: number | null;
  credential_name: string;
  verify_tls: boolean;
  has_ca_pem: boolean;
  timeout_seconds: number;
  description: string;
  last_test_at: string;
  last_test_ok: boolean | null;
  last_test_message: string;
  job_count: number;
}

export interface SyncConnectionInput {
  name: string;
  kind: SyncKind;
  base_url: string;
  auth_type: SyncConnection['auth_type'];
  credential_id: number | null;
  verify_tls: boolean;
  /** `null` keeps the stored bundle; `''` removes it. */
  ca_pem: string | null;
  timeout_seconds: number;
  description: string;
}

/** Field name -> remote path (`true`: on at the default path, `false`: off); `_endpoint` etc. are options. */
export type TypeMapping = Record<string, string | boolean | null | Record<string, unknown>>;

export interface SyncJob extends Stamps {
  id: number;
  name: string;
  connection_id: number;
  connection_name: string;
  connection_kind: SyncKind;
  object_types: SyncObjectType[];
  direction: SyncDirection;
  conflict_policy: SyncPolicy;
  delete_missing: boolean;
  mappings: Partial<Record<SyncObjectType, TypeMapping>>;
  options: { host_group?: string };
  interval_minutes: number;
  enabled: boolean;
  description: string;
  last_run_id: number | null;
  last_run_status: string;
  last_run_at: string;
  last_attempt_at: string;
  running: boolean;
}

export interface SyncJobInput {
  name: string;
  connection_id: number;
  object_types: SyncObjectType[];
  direction: SyncDirection;
  conflict_policy: SyncPolicy;
  delete_missing: boolean;
  mappings: Partial<Record<SyncObjectType, TypeMapping>>;
  host_group: string;
  interval_minutes: number;
  enabled: boolean;
  description: string;
}

/** Counts of one object type in a run (or `error` when the type could not be read). */
export interface SyncTypeSummary {
  error?: string;
  remote_records?: number;
  plexus_records?: number;
  unchanged?: number;
  create?: number;
  update?: number;
  delete?: number;
  conflict?: number;
  planned?: number;
  applied?: number;
  failed?: number;
  skipped?: number;
  fields?: string[];
  warnings?: string[];
}

export interface SyncRun {
  id: number;
  job_id: number;
  job_name: string;
  dry_run: boolean;
  trigger: 'manual' | 'schedule' | string;
  status: 'running' | 'success' | 'partial' | 'failed' | string;
  started_by: string;
  started_at: string;
  finished_at: string;
  summary: Partial<Record<SyncObjectType, SyncTypeSummary>>;
  message: string;
}

/** `{before, after}` per field; a conflict carries `{plexus, remote}`. */
export type SyncFieldChange = { before?: string; after?: string; plexus?: string; remote?: string };

export interface SyncRunEntry {
  id: number;
  object_type: SyncObjectType;
  key: string;
  action: SyncAction;
  target: 'plexus' | 'remote';
  changes: Record<string, SyncFieldChange>;
  outcome: SyncOutcome;
  message: string;
}

export interface SyncEntryPage {
  entries: SyncRunEntry[];
  total: number;
  limit: number;
  offset: number;
}

export interface SyncCatalog {
  kinds: { id: SyncKind; label: string; auth_types: SyncConnection['auth_type'][]; notes: string }[];
  object_types: { id: SyncObjectType; label: string; key: string[]; fields: string[]; optional: string[] }[];
  directions: SyncDirection[];
  conflict_policies: SyncPolicy[];
  default_mappings: Record<
    SyncKind,
    Record<SyncObjectType, { endpoint: string; paths: Record<string, string>; read_only: string[]; optional: string[] }>
  >;
  interval_min: number;
  interval_max: number;
}

// ── Queries ────────────────────────────────────────────────────────────────

const ROOT = ['sync'] as const;
export const SYNC_KEYS = {
  catalog: [...ROOT, 'catalog'] as const,
  connections: [...ROOT, 'connections'] as const,
  jobs: [...ROOT, 'jobs'] as const,
  runs: (jobId: number | null) => [...ROOT, 'runs', jobId ?? 'all'] as const,
  run: (id: number) => [...ROOT, 'run', id] as const,
  entries: (id: number, filter: object) => [...ROOT, 'entries', id, filter] as const,
};

function invalidateAll(qc: QueryClient) {
  return qc.invalidateQueries({ queryKey: ROOT });
}

export function useSyncCatalog() {
  return useQuery<SyncCatalog>({
    queryKey: SYNC_KEYS.catalog,
    queryFn: () => detailRequest<SyncCatalog>('/sync/catalog'),
    staleTime: Infinity,
  });
}

export function useSyncConnections() {
  return useQuery<SyncConnection[]>({
    queryKey: SYNC_KEYS.connections,
    queryFn: async () => listOf<SyncConnection>(await detailRequest('/sync/connections'), 'connections'),
  });
}

export function useSyncJobs() {
  return useQuery<SyncJob[]>({
    queryKey: SYNC_KEYS.jobs,
    queryFn: async () => listOf<SyncJob>(await detailRequest('/sync/jobs'), 'jobs'),
    // A running job finishes in the background: poll until none runs.
    refetchInterval: (q) => (q.state.data?.some((j) => j.running) ? 3000 : false),
  });
}

export function useSyncRuns(jobId: number | null) {
  return useQuery<SyncRun[]>({
    queryKey: SYNC_KEYS.runs(jobId),
    queryFn: async () =>
      listOf<SyncRun>(await detailRequest(`/sync/runs${queryString({ job_id: jobId ?? undefined })}`), 'runs'),
    refetchInterval: (q) => (q.state.data?.some((r) => r.status === 'running') ? 3000 : false),
  });
}

export function useSyncRun(id: number | null) {
  return useQuery<SyncRun>({
    queryKey: SYNC_KEYS.run(id ?? 0),
    queryFn: () => detailRequest<SyncRun>(`/sync/runs/${id}`),
    enabled: id !== null,
    // Poll a run that is still going so its outcome shows when it ends.
    refetchInterval: (q) => (q.state.data?.status === 'running' ? 2000 : false),
  });
}

export interface EntryFilter {
  object_type?: SyncObjectType;
  outcome?: SyncOutcome;
  limit: number;
  offset: number;
}

export function useSyncRunEntries(id: number | null, filter: EntryFilter, enabled = true) {
  return useQuery<SyncEntryPage>({
    queryKey: SYNC_KEYS.entries(id ?? 0, filter),
    queryFn: () => detailRequest<SyncEntryPage>(`/sync/runs/${id}/entries${queryString(filter)}`),
    enabled: enabled && id !== null,
  });
}

// ── Mutations ──────────────────────────────────────────────────────────────

function useWrite<TBody, TResult = unknown>(request: (body: TBody) => Promise<TResult>) {
  const qc = useQueryClient();
  return useMutation<TResult, Error, TBody>({ mutationFn: request, onSuccess: () => invalidateAll(qc) });
}

export function useSaveSyncConnection() {
  return useWrite<{ id: number | null; data: SyncConnectionInput }, SyncConnection>(({ id, data }) =>
    detailRequest<SyncConnection>(id === null ? '/sync/connections' : `/sync/connections/${id}`, {
      method: id === null ? 'POST' : 'PUT',
      body: data,
    }),
  );
}

/** Refused with a 409 while jobs use the connection. */
export function useDeleteSyncConnection() {
  return useWrite<number>((id) => detailRequest(`/sync/connections/${id}`, { method: 'DELETE' }));
}

export function useTestSyncConnection() {
  return useWrite<number, { ok: boolean; message: string }>((id) =>
    detailRequest(`/sync/connections/${id}/test`, { method: 'POST' }),
  );
}

export function useSaveSyncJob() {
  return useWrite<{ id: number | null; data: SyncJobInput }, SyncJob>(({ id, data }) =>
    detailRequest<SyncJob>(id === null ? '/sync/jobs' : `/sync/jobs/${id}`, {
      method: id === null ? 'POST' : 'PUT',
      body: data,
    }),
  );
}

export function useDeleteSyncJob() {
  return useWrite<number>((id) => detailRequest(`/sync/jobs/${id}`, { method: 'DELETE' }));
}

/** Starts a run (answers with it while it runs); 409 when the job is already running. */
export function useRunSyncJob() {
  return useWrite<{ id: number; dryRun: boolean }, SyncRun>(({ id, dryRun }) =>
    detailRequest<SyncRun>(`/sync/jobs/${id}/run`, { method: 'POST', body: { dry_run: dryRun } }),
  );
}
