import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

export type UpdateChannel = 'release' | 'edge' | 'git' | 'disabled';

export interface UpdatesConfig {
  channel: UpdateChannel;
  repo: string;
  git_remote: string;
  git_branch: string;
  image_repo: string;
}

export interface CurrentVersion {
  version: string;
  git_sha: string | null;
}

export interface CheckResult {
  ok: boolean;
  channel: UpdateChannel;
  current: CurrentVersion;
  is_newer?: boolean;
  latest_version?: string;
  latest_name?: string;
  release_notes?: string;
  published_at?: string | null;
  html_url?: string | null;
  commits_behind?: number;
  local_sha?: string;
  error?: string;
}

export interface UpdatesStatus {
  current: CurrentVersion;
  channel: UpdateChannel;
  repo: string;
  last_check: CheckResult | null;
}

export function useUpdatesStatus() {
  return useQuery<UpdatesStatus>({
    queryKey: ['admin', 'updates', 'status'],
    queryFn: () => apiRequest('/admin/updates/status'),
  });
}

export function useUpdatesConfig() {
  return useQuery<UpdatesConfig>({
    queryKey: ['admin', 'updates', 'config'],
    queryFn: () => apiRequest('/admin/updates/config'),
  });
}

export function useSaveUpdatesConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: UpdatesConfig) =>
      apiRequest<UpdatesConfig>('/admin/updates/config', {
        method: 'PUT',
        body: data,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'updates'] });
    },
  });
}

export function useCheckForUpdates() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiRequest<CheckResult>('/admin/updates/check', { method: 'POST' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'updates', 'status'] });
    },
  });
}

export interface UpdateRequest {
  id: string;
  action: 'upgrade' | 'rollback';
  mode: 'image' | 'git' | '';
  image?: string;
  ref?: string;
  channel: string;
  target_version: string;
  requested_by: string;
  requested_at: string;
}

export interface UpdateResult {
  id: string | null;
  status: 'running' | 'success' | 'failed';
  started_at: string | null;
  finished_at: string | null;
  exit_code: number | null;
  message: string;
  request: UpdateRequest | null;
}

export interface UpdateProgress {
  agent_installed: boolean;
  pending: UpdateRequest | null;
  in_progress: UpdateRequest | null;
  result: UpdateResult | null;
  log_tail: string;
  rollback_available: boolean;
  rollback: { mode: string | null; target: string | null; recorded_at: string | null } | null;
  current: CurrentVersion;
}

export function isUpdateBusy(p: UpdateProgress | undefined): boolean {
  return !!p && (p.pending != null || p.in_progress != null || p.result?.status === 'running');
}

export function useUpdateProgress() {
  return useQuery<UpdateProgress>({
    queryKey: ['admin', 'updates', 'progress'],
    queryFn: () => apiRequest('/admin/updates/progress'),
    // The host updater runs outside the app; poll fast only while it works.
    refetchInterval: (query) => (isUpdateBusy(query.state.data) ? 3000 : 15000),
  });
}

export function useAppVersion(poll: boolean) {
  return useQuery<CurrentVersion>({
    queryKey: ['app-version'],
    queryFn: () => apiRequest('/version'),
    // While an upgrade runs, watch for the restarted container's new version.
    refetchInterval: poll ? 3000 : false,
    retry: false,
  });
}

export function useApplyUpdate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (target: string) =>
      apiRequest<UpdateRequest>('/admin/updates/apply', {
        method: 'POST',
        body: { target },
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'updates', 'progress'] });
    },
  });
}

export function useRollbackUpdate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiRequest<UpdateRequest>('/admin/updates/rollback', { method: 'POST' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'updates', 'progress'] });
    },
  });
}
