import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

// ── Types ──────────────────────────────────────────────────────────────────

export interface ConfigDriftSummary {
  total_baselined?: number;
  compliant?: number;
  drifted?: number;
  open_events?: number;
}

export interface ConfigDriftEvent {
  id: number;
  host_id: number;
  hostname?: string | null;
  ip_address?: string | null;
  device_type?: string | null;
  status: 'open' | 'accepted' | 'resolved' | string;
  detected_at?: string | null;
  diff_text?: string | null;
  diff_lines_added?: number;
  diff_lines_removed?: number;
}

export interface ConfigDriftEventHistoryEntry {
  created_at?: string | null;
  actor?: string | null;
  action?: string | null;
  from_status?: string | null;
  to_status?: string | null;
  details?: string | null;
}

export interface ConfigSnapshot {
  id: number;
  host_id: number;
  hostname?: string | null;
  captured_at?: string | null;
  capture_method?: string | null;
  config_text?: string;
  config_length?: number;
}

export interface ConfigBackupSummary {
  total_policies?: number;
  total_backups?: number;
  hosts_backed_up?: number;
  last_backup_at?: string | null;
}

export interface ConfigBackupPolicy {
  id: number;
  name: string;
  group_id: number;
  group_name?: string | null;
  credential_id: number;
  enabled: boolean;
  interval_seconds: number;
  retention_days: number;
  last_run_at?: string | null;
  host_count?: number;
}

export interface ConfigBackup {
  id: number;
  host_id?: number;
  hostname?: string | null;
  ip_address?: string | null;
  policy_id?: number | null;
  captured_at: string;
  capture_method?: string;
  status: 'success' | 'failed' | string;
  config_length?: number;
  error_message?: string | null;
}

export interface ConfigBackupDetail extends ConfigBackup {
  config_text?: string;
}

export interface ConfigBackupDiff {
  hostname?: string | null;
  ip_address?: string | null;
  captured_at?: string | null;
  previous_captured_at?: string | null;
  diff_text?: string | null;
  diff_lines_added?: number;
  diff_lines_removed?: number;
}

export interface ConfigBackupSearchResult {
  backup_id: number;
  hostname?: string | null;
  ip_address?: string | null;
  captured_at?: string | null;
  capture_method?: string;
  config_length?: number;
  match_line?: string;
  match_line_number?: number;
  context_before_lines?: string[];
  context_after_lines?: string[];
}

export interface ConfigBackupSearchPayload {
  results: ConfigBackupSearchResult[];
  has_more?: boolean;
  mode?: string;
}

export interface BackupPolicyCreatePayload {
  name: string;
  group_id: number;
  credential_id: number;
  interval_seconds: number;
  retention_days: number;
}

export interface BackupPolicyUpdatePayload {
  name?: string;
  enabled?: boolean;
  credential_id?: number;
  interval_seconds?: number;
  retention_days?: number;
}

export interface RunBackupPolicyResult {
  backed_up: number;
  errors: number;
  skipped?: number;
}

export interface RestoreBackupResult {
  hostname?: string;
  validated: boolean;
  lines_changed?: number;
  diff_text?: string;
}

// ── Queries ────────────────────────────────────────────────────────────────

export function useConfigDriftSummary() {
  return useQuery<ConfigDriftSummary>({
    queryKey: ['config-drift-summary'],
    queryFn: () => apiRequest('/config-drift/summary'),
  });
}

export function useConfigDriftEvents(status: string, limit = 200) {
  const params = new URLSearchParams();
  if (status && status !== 'all') params.set('status', status);
  params.set('limit', String(limit));
  return useQuery<ConfigDriftEvent[]>({
    queryKey: ['config-drift-events', status, limit],
    queryFn: () => apiRequest(`/config-drift/events?${params}`),
  });
}

export function useConfigDriftEvent(eventId: number | null) {
  return useQuery<ConfigDriftEvent>({
    queryKey: ['config-drift-event', eventId],
    queryFn: () => apiRequest(`/config-drift/events/${eventId}`),
    enabled: eventId != null,
  });
}

export function useConfigDriftEventHistory(eventId: number | null, limit = 200) {
  return useQuery<ConfigDriftEventHistoryEntry[]>({
    queryKey: ['config-drift-event-history', eventId, limit],
    queryFn: () =>
      apiRequest(`/config-drift/events/${eventId}/history?limit=${limit}`),
    enabled: eventId != null,
  });
}

export function useConfigSnapshots(hostId: number | null, limit = 20) {
  return useQuery<ConfigSnapshot[]>({
    queryKey: ['config-snapshots', hostId, limit],
    queryFn: () =>
      apiRequest(`/config-drift/snapshots?host_id=${hostId}&limit=${limit}`),
    enabled: hostId != null,
  });
}

export function useConfigSnapshot(snapshotId: number | null) {
  return useQuery<ConfigSnapshot>({
    queryKey: ['config-snapshot', snapshotId],
    queryFn: () => apiRequest(`/config-drift/snapshots/${snapshotId}`),
    enabled: snapshotId != null,
  });
}

export function useConfigBackupSummary() {
  return useQuery<ConfigBackupSummary>({
    queryKey: ['config-backup-summary'],
    queryFn: () => apiRequest('/config-backups/summary'),
  });
}

export function useConfigBackupPolicies() {
  return useQuery<ConfigBackupPolicy[]>({
    queryKey: ['config-backup-policies'],
    queryFn: () => apiRequest('/config-backups/policies?'),
  });
}

export function useConfigBackups(limit = 100) {
  const params = new URLSearchParams();
  params.set('limit', String(limit));
  return useQuery<ConfigBackup[]>({
    queryKey: ['config-backups', limit],
    queryFn: () => apiRequest(`/config-backups?${params}`),
  });
}

export function useConfigBackupDetail(id: number | null) {
  return useQuery<ConfigBackupDetail>({
    queryKey: ['config-backup', id],
    queryFn: () => apiRequest(`/config-backups/${id}`),
    enabled: id != null,
  });
}

export function useConfigBackupDiff(id: number | null) {
  return useQuery<ConfigBackupDiff>({
    queryKey: ['config-backup-diff', id],
    queryFn: () => apiRequest(`/config-backups/${id}/diff`),
    enabled: id != null,
  });
}

export function configBackupDownloadUrl(id: number): string {
  return `/api/config-backups/${id}/download`;
}

export function configBackupBulkDownloadUrl(): string {
  return '/api/config-backups/download';
}

// ── Mutations ──────────────────────────────────────────────────────────────

function invalidateDrift(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: ['config-drift-summary'] });
  qc.invalidateQueries({ queryKey: ['config-drift-events'] });
  qc.invalidateQueries({ queryKey: ['config-drift-event'] });
  qc.invalidateQueries({ queryKey: ['config-drift-event-history'] });
}

function invalidateBackups(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: ['config-backup-summary'] });
  qc.invalidateQueries({ queryKey: ['config-backup-policies'] });
  qc.invalidateQueries({ queryKey: ['config-backups'] });
}

export function useUpdateDriftEventStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status }: { id: number; status: string }) =>
      apiRequest(`/config-drift/events/${id}/status`, {
        method: 'PUT',
        body: { status },
      }),
    onSuccess: () => invalidateDrift(qc),
  });
}

export function useBulkAcceptDriftEvents() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (eventIds: number[]) =>
      apiRequest<{ accepted: number }>('/config-drift/events/bulk-accept', {
        method: 'POST',
        body: { event_ids: eventIds },
      }),
    onSuccess: () => invalidateDrift(qc),
  });
}

export function useRevertDriftEvent() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      eventId,
      credentialId,
    }: {
      eventId: number;
      credentialId: number;
    }) =>
      apiRequest<{ job_id: string }>('/config-drift/events/revert', {
        method: 'POST',
        body: { event_id: eventId, credential_id: credentialId },
      }),
    onSuccess: () => invalidateDrift(qc),
  });
}

export function useCreateConfigBaseline() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: {
      host_id: number;
      name?: string;
      config_text: string;
      source?: string;
    }) =>
      apiRequest('/config-drift/baselines', {
        method: 'POST',
        body: { source: 'manual', ...data },
      }),
    onSuccess: () => invalidateDrift(qc),
  });
}

export function useStartCaptureSingleJob() {
  return useMutation({
    mutationFn: ({
      hostId,
      credentialId,
    }: {
      hostId: number;
      credentialId: number;
    }) =>
      apiRequest<{ job_id: string }>(
        '/config-drift/snapshots/capture-single-job',
        {
          method: 'POST',
          body: { host_id: hostId, credential_id: credentialId },
        },
      ),
  });
}

export function useStartCaptureGroupJob() {
  return useMutation({
    mutationFn: ({
      groupId,
      credentialId,
    }: {
      groupId: number;
      credentialId: number;
    }) =>
      apiRequest<{ job_id: string }>('/config-drift/snapshots/capture-job', {
        method: 'POST',
        body: { group_id: groupId, credential_id: credentialId },
      }),
  });
}

export function useCreateBackupPolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: BackupPolicyCreatePayload) =>
      apiRequest('/config-backups/policies', { method: 'POST', body: data }),
    onSuccess: () => invalidateBackups(qc),
  });
}

export function useUpdateBackupPolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: BackupPolicyUpdatePayload }) =>
      apiRequest(`/config-backups/policies/${id}`, {
        method: 'PUT',
        body: data,
      }),
    onSuccess: () => invalidateBackups(qc),
  });
}

export function useDeleteBackupPolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/config-backups/policies/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateBackups(qc),
  });
}

export function useRunBackupPolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest<RunBackupPolicyResult>(
        `/config-backups/policies/${id}/run-now`,
        { method: 'POST' },
      ),
    onSuccess: () => invalidateBackups(qc),
  });
}

export function useDeleteBackup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/config-backups/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateBackups(qc),
  });
}

export function useRestoreBackup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      backupId,
      credentialId,
    }: {
      backupId: number;
      credentialId: number;
    }) =>
      apiRequest<RestoreBackupResult>('/config-backups/restore', {
        method: 'POST',
        body: { backup_id: backupId, credential_id: credentialId },
      }),
    onSuccess: () => invalidateBackups(qc),
  });
}

export function useSearchConfigBackups() {
  return useMutation({
    mutationFn: ({
      query,
      mode,
      limit,
      contextLines,
    }: {
      query: string;
      mode: string;
      limit: number;
      contextLines: number;
    }) => {
      const params = new URLSearchParams();
      params.set('q', query);
      params.set('mode', mode);
      params.set('limit', String(limit));
      params.set('context_lines', String(contextLines));
      return apiRequest<ConfigBackupSearchPayload>(
        `/config-backups/search?${params}`,
      );
    },
  });
}
