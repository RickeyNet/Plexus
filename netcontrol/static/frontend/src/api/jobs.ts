/**
 * Jobs API - playbooks, jobs, templates, credentials, secret variables.
 *
 * Mirrors legacy api.js. Job output streaming is handled inline by the
 * Jobs page via a WebSocket on /ws/jobs/<id>; only REST is exposed here.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

// ── Types ──────────────────────────────────────────────────────────────────

export type PlaybookType = 'python' | 'ansible';

export interface Playbook {
  id: number;
  name: string;
  filename: string;
  description?: string | null;
  tags?: string[] | string | null;
  content?: string;
  type?: PlaybookType;
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
}

export interface PlaybookUpdate {
  name?: string;
  filename?: string;
  description?: string;
  tags?: string[];
  content?: string;
  type?: PlaybookType;
}

export type JobStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | string;

export interface Job {
  id: number;
  playbook_id?: number;
  playbook_name?: string;
  group_name?: string;
  status: JobStatus;
  dry_run?: boolean;
  priority?: number;
  depends_on?: string | null;
  started_at?: string | null;
  queued_at?: string | null;
  completed_at?: string | null;
  launched_by?: string | null;
}

export interface JobLaunchBody {
  playbook_id: number;
  inventory_group_id?: number;
  credential_id?: number;
  template_id?: number;
  dry_run: boolean;
  host_ids?: number[];
  priority?: number;
  depends_on?: number[];
  ad_hoc_ips?: string[];
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

export interface ConfigTemplate {
  id: number;
  name: string;
  description?: string;
  content: string;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface Credential {
  id: number;
  name: string;
  username: string;
  created_at?: string | null;
}

export interface SecretVariable {
  id: number;
  name: string;
  description?: string | null;
  created_by?: string | null;
  created_at?: string | null;
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
    mutationFn: (body: PlaybookCreate) =>
      apiRequest<Playbook>('/playbooks', { method: 'POST', body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['playbooks'] }),
  });
}

export function useUpdatePlaybook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: PlaybookUpdate }) =>
      apiRequest<Playbook>(`/playbooks/${id}`, { method: 'PUT', body: data }),
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

export function useJobs(limit = 100) {
  return useQuery<Job[]>({
    queryKey: ['jobs', limit],
    queryFn: () => apiRequest<Job[]>(`/jobs?limit=${limit}`),
    refetchInterval: 10_000,
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
    refetchInterval: 5_000,
  });
}

export function useLaunchJob() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: JobLaunchBody) =>
      apiRequest<JobLaunchResult>('/jobs/launch', { method: 'POST', body }),
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
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['jobs'] });
      qc.invalidateQueries({ queryKey: ['job-queue'] });
    },
  });
}

export function useRetryJob() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest<JobLaunchResult>(`/jobs/${id}/retry`, { method: 'POST' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['jobs'] });
      qc.invalidateQueries({ queryKey: ['job-queue'] });
    },
  });
}

export function useRerunJobLive() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest<JobLaunchResult>(`/jobs/${id}/rerun`, { method: 'POST' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['jobs'] });
      qc.invalidateQueries({ queryKey: ['job-queue'] });
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
    mutationFn: (body: { name: string; content: string; description?: string }) =>
      apiRequest<ConfigTemplate>('/templates', { method: 'POST', body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['config-templates'] }),
  });
}

export function useUpdateTemplate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: { name: string; content: string; description?: string } }) =>
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
    mutationFn: (body: { name: string; username: string; password: string; secret?: string }) =>
      apiRequest<Credential>('/credentials', { method: 'POST', body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['credentials'] }),
  });
}

export function useUpdateCredential() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: Partial<{ name: string; username: string; password: string; secret: string }> }) =>
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

export function useSecretVariables() {
  return useQuery<SecretVariable[]>({
    queryKey: ['secret-variables'],
    queryFn: () => apiRequest<SecretVariable[]>('/secret-variables'),
  });
}

export function useCreateSecretVariable() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { name: string; value: string; description?: string }) =>
      apiRequest<SecretVariable>('/secret-variables', { method: 'POST', body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['secret-variables'] }),
  });
}

export function useUpdateSecretVariable() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: { value?: string; description?: string } }) =>
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

export const JOB_PRIORITY_COLORS: Record<number, string> = {
  0: 'text-muted',
  1: 'text-muted',
  2: 'primary',
  3: 'warning',
  4: 'danger',
};
