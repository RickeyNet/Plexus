/**
 * Jobs API - playbooks, jobs, templates, credentials, secret variables.
 *
 * Mirrors legacy api.js. Job output streaming is handled inline by the
 * Jobs page via a WebSocket on /ws/jobs/<id>; only REST is exposed here.
 */
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import type { ExternalReferenceBody, ReferencedRow } from '@/lib/secretsProviders';
import type { Tone } from '@/lib/severity';

import { apiRequest } from './client';
import { detailRequest } from './customData';
import type { GitOwnership } from './gitSources';

// ── Types ──────────────────────────────────────────────────────────────────

export type PlaybookType = 'python' | 'ansible';

/** A typed run-dialog input (netcontrol/job_inputs.py). */
export type JobInputType =
  | 'string'
  | 'text'
  | 'integer'
  | 'boolean'
  | 'choice'
  | 'multichoice'
  | 'list'
  | 'ip'
  | 'cidr'
  | 'host'
  | 'group'
  | 'secret';

export interface JobInputField {
  name: string;
  type: JobInputType;
  label: string;
  help?: string;
  required?: boolean;
  default?: string | number | boolean | string[] | null;
  choices?: string[];
  /** Integer value, string/text length, or multichoice/list item count. */
  min?: number;
  max?: number;
  /** String and text only; must match the whole value. */
  regex?: string;
}

export interface JobPermissionRule {
  roles: string[];
  /** Access group ids. */
  groups: number[];
}

/** Who may run the job, and who may commit (run it live). Empty rule = anyone with `jobs`. */
export interface JobPermissions {
  run: JobPermissionRule;
  commit: JobPermissionRule;
}

export interface Playbook extends GitOwnership {
  id: number;
  name: string;
  filename: string;
  description?: string | null;
  tags?: string[] | string | null;
  content?: string;
  type?: PlaybookType;
  parameters_schema?: JobInputField[];
  /** The effective typed input schema (stored on the task, else declared in code). */
  input_schema?: JobInputField[];
  input_schema_source?: 'stored' | 'code' | 'none';
  /** False: the task cannot preview, so it only runs with commit. */
  supports_dry_run?: boolean;
  permissions?: JobPermissions;
  /** Whether the signed-in user may run / commit this task. */
  can_run?: boolean;
  can_commit?: boolean;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface PlaybookCreate {
  name: string;
  filename: string;
  description?: string;
  tags?: string[];
  content: string;
  type?: PlaybookType;
  input_schema?: JobInputField[];
  /** Admin only. */
  permissions?: JobPermissions;
}

export interface PlaybookUpdate {
  name?: string;
  filename?: string;
  description?: string;
  tags?: string[];
  content?: string;
  type?: PlaybookType;
  input_schema?: JobInputField[];
  /** Admin only. */
  permissions?: JobPermissions;
}

export type JobStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | string;

export interface Job {
  id: number;
  playbook_id?: number;
  playbook_name?: string;
  group_name?: string;
  /** The dynamic group the job targets (its hosts are resolved when it starts). */
  dynamic_group_id?: number | null;
  dynamic_group_name?: string | null;
  status: JobStatus;
  dry_run?: boolean;
  priority?: number;
  depends_on?: string | null;
  started_at?: string | null;
  queued_at?: string | null;
  completed_at?: string | null;
  launched_by?: string | null;
  /** The validated inputs as JSON text; secret inputs are `{{secret.NAME}}` references. */
  parameters?: string | null;
}

export interface JobLaunchBody {
  playbook_id: number;
  inventory_group_id?: number;
  credential_id?: number;
  template_id?: number;
  /** True runs live; omitted or false is a dry run. */
  commit?: boolean;
  /** Legacy; `commit` wins when both are sent. */
  dry_run?: boolean;
  host_ids?: number[];
  /** A dynamic group: its hosts are resolved when the job starts (instead of `host_ids`). */
  dynamic_group_id?: number;
  priority?: number;
  depends_on?: number[];
  ad_hoc_ips?: string[];
  /** Values for the task's typed inputs. A bad value answers 422 with `detail.fields`. */
  inputs?: Record<string, unknown>;
  /** Legacy name for `inputs`. */
  parameters?: Record<string, unknown>;
}

export interface JobLaunchResult {
  job_id: number;
}

export interface JobEvent {
  id?: number;
  job_id?: number;
  level: string;
  message: string;
  host?: string | null;
  timestamp: string;
}

export interface JobQueueChip {
  id: number;
  playbook_name?: string;
  status: JobStatus;
  priority?: number;
}

export interface JobQueueData {
  running: number;
  queued: number;
  max_concurrent: number;
  jobs: JobQueueChip[];
}

export interface ConfigTemplate extends GitOwnership {
  id: number;
  name: string;
  description?: string;
  content: string;
  // Empty = generic body (applied to any vendor).  A Netmiko
  // device_type string (e.g. "paloalto_panos") makes this a
  // vendor-specific variant of the same name; at job run time the
  // body matching each host's platform is resolved automatically.
  device_type?: string;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface TemplatePayload {
  name: string;
  content: string;
  description?: string;
  device_type?: string;
}

/** `ext_*`: the external secrets provider reference, when the value is not
 *  stored in Plexus (docs/secrets-providers.md). */
export interface Credential extends ReferencedRow {
  id: number;
  name: string;
  username: string;
  created_at?: string | null;
}

export interface SecretVariable extends ReferencedRow {
  id: number;
  name: string;
  description?: string | null;
  created_by?: string | null;
  created_at?: string | null;
}

export interface CredentialPayload {
  name: string;
  username: string;
  password?: string;
  secret?: string;
  external?: ExternalReferenceBody;
}

export interface SecretVariablePayload {
  name: string;
  value?: string;
  description?: string;
  external?: ExternalReferenceBody;
}

// ── Playbooks ──────────────────────────────────────────────────────────────

export function usePlaybooks() {
  return useQuery<Playbook[]>({
    queryKey: ['playbooks'],
    queryFn: () => apiRequest<Playbook[]>('/playbooks'),
  });
}

export function usePlaybook(id: number | null) {
  return useQuery<Playbook>({
    queryKey: ['playbook', id],
    queryFn: () => apiRequest<Playbook>(`/playbooks/${id}`),
    enabled: id != null,
  });
}

export function useCreatePlaybook() {
  const qc = useQueryClient();
  return useMutation({
    // detailRequest: a bad input schema answers 422 with per-field messages.
    mutationFn: (body: PlaybookCreate) =>
      detailRequest<Playbook>('/playbooks', { method: 'POST', body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['playbooks'] }),
  });
}

export function useUpdatePlaybook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: PlaybookUpdate }) =>
      detailRequest<Playbook>(`/playbooks/${id}`, { method: 'PUT', body: data }),
    onSuccess: (_d, vars) => {
      qc.invalidateQueries({ queryKey: ['playbooks'] });
      qc.invalidateQueries({ queryKey: ['playbook', vars.id] });
    },
  });
}

export function useDeletePlaybook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest<{ ok: boolean }>(`/playbooks/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['playbooks'] }),
  });
}

// ── Jobs ───────────────────────────────────────────────────────────────────

/** The most jobs GET /api/jobs returns in one call (the route's `limit` ceiling). */
export const JOB_LIST_MAX = 200;

export function useJobs(limit = 100) {
  return useQuery<Job[]>({
    queryKey: ['jobs', limit],
    queryFn: () => apiRequest<Job[]>(`/jobs?limit=${limit}`),
    refetchInterval: 30_000,
    // Keep the list on screen while a larger page loads.
    placeholderData: keepPreviousData,
  });
}

export function useJob(id: number | null) {
  return useQuery<Job>({
    queryKey: ['job', id],
    queryFn: () => apiRequest<Job>(`/jobs/${id}`),
    enabled: id != null,
  });
}

export function useJobEvents(id: number | null) {
  return useQuery<JobEvent[]>({
    queryKey: ['job-events', id],
    queryFn: () => apiRequest<JobEvent[]>(`/jobs/${id}/events`),
    enabled: id != null,
  });
}

export function useJobQueue() {
  return useQuery<JobQueueData>({
    queryKey: ['job-queue'],
    queryFn: () => apiRequest<JobQueueData>('/jobs/queue'),
    refetchInterval: 15_000,
  });
}

export function useLaunchJob() {
  const qc = useQueryClient();
  return useMutation({
    // detailRequest: invalid inputs answer 422 with per-field messages.
    mutationFn: (body: JobLaunchBody) =>
      detailRequest<JobLaunchResult>('/jobs/launch', { method: 'POST', body }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['jobs'] });
      qc.invalidateQueries({ queryKey: ['job-queue'] });
    },
  });
}

export function useCancelJob() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest<{ ok: boolean }>(`/jobs/${id}/cancel`, { method: 'POST' }),
    // Invalidate the single-job queries too, not just the lists: an open
    // JobOutputModal reads ['job', id] and would otherwise keep showing the
    // job as running (with the Cancel button still live) after it's cancelled.
    onSuccess: (_data, id) => {
      qc.invalidateQueries({ queryKey: ['jobs'] });
      qc.invalidateQueries({ queryKey: ['job-queue'] });
      qc.invalidateQueries({ queryKey: ['job', id] });
      qc.invalidateQueries({ queryKey: ['job-events', id] });
    },
  });
}

export function useRetryJob() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest<JobLaunchResult>(`/jobs/${id}/retry`, { method: 'POST' }),
    onSuccess: (_data, id) => {
      qc.invalidateQueries({ queryKey: ['jobs'] });
      qc.invalidateQueries({ queryKey: ['job-queue'] });
      qc.invalidateQueries({ queryKey: ['job', id] });
      qc.invalidateQueries({ queryKey: ['job-events', id] });
    },
  });
}

export function useRerunJobLive() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest<JobLaunchResult>(`/jobs/${id}/rerun`, { method: 'POST' }),
    onSuccess: (_data, id) => {
      qc.invalidateQueries({ queryKey: ['jobs'] });
      qc.invalidateQueries({ queryKey: ['job-queue'] });
      qc.invalidateQueries({ queryKey: ['job', id] });
      qc.invalidateQueries({ queryKey: ['job-events', id] });
    },
  });
}

// ── Templates ──────────────────────────────────────────────────────────────

export function useTemplates() {
  return useQuery<ConfigTemplate[]>({
    queryKey: ['config-templates'],
    queryFn: () => apiRequest<ConfigTemplate[]>('/templates'),
  });
}

export function useTemplate(id: number | null) {
  return useQuery<ConfigTemplate>({
    queryKey: ['config-template', id],
    queryFn: () => apiRequest<ConfigTemplate>(`/templates/${id}`),
    enabled: id != null,
  });
}

export function useCreateTemplate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: TemplatePayload) =>
      apiRequest<ConfigTemplate>('/templates', { method: 'POST', body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['config-templates'] }),
  });
}

export function useUpdateTemplate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: TemplatePayload }) =>
      apiRequest<ConfigTemplate>(`/templates/${id}`, { method: 'PUT', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['config-templates'] }),
  });
}

export function useDeleteTemplate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest<{ ok: boolean }>(`/templates/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['config-templates'] }),
  });
}

// ── Credentials ────────────────────────────────────────────────────────────

export function useJobCredentials() {
  return useQuery<Credential[]>({
    queryKey: ['credentials'],
    queryFn: () => apiRequest<Credential[]>('/credentials'),
  });
}

export function useCreateCredential() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CredentialPayload) => apiRequest<Credential>('/credentials', { method: 'POST', body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['credentials'] }),
  });
}

export function useUpdateCredential() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: Partial<CredentialPayload> }) =>
      apiRequest<Credential>(`/credentials/${id}`, { method: 'PUT', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['credentials'] }),
  });
}

export function useDeleteCredential() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest<{ ok: boolean }>(`/credentials/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['credentials'] }),
  });
}

// ── Secret Variables ───────────────────────────────────────────────────────

/** `enabled` false skips the request (the list is admin only). */
export function useSecretVariables(enabled = true) {
  return useQuery<SecretVariable[]>({
    queryKey: ['secret-variables'],
    queryFn: () => apiRequest<SecretVariable[]>('/secret-variables'),
    enabled,
  });
}

export function useCreateSecretVariable() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: SecretVariablePayload) =>
      apiRequest<SecretVariable>('/secret-variables', { method: 'POST', body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['secret-variables'] }),
  });
}

export function useUpdateSecretVariable() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: Omit<Partial<SecretVariablePayload>, 'name'> }) =>
      apiRequest<SecretVariable>(`/secret-variables/${id}`, { method: 'PUT', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['secret-variables'] }),
  });
}

export function useDeleteSecretVariable() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest<{ ok: boolean }>(`/secret-variables/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['secret-variables'] }),
  });
}

// ── Constants ──────────────────────────────────────────────────────────────

export const JOB_PRIORITY_LABELS: Record<number, string> = {
  0: 'Low',
  1: 'Below Normal',
  2: 'Normal',
  3: 'High',
  4: 'Critical',
};

export const JOB_PRIORITY_TONES: Record<number, Tone> = {
  0: 'neutral',
  1: 'neutral',
  2: 'primary',
  3: 'warning',
  4: 'danger',
};
