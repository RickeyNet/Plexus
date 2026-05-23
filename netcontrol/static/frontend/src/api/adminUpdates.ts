import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

export type UpdateChannel = 'release' | 'git' | 'disabled';

export interface UpdatesConfig {
  channel: UpdateChannel;
  repo: string;
  git_remote: string;
  git_branch: string;
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
