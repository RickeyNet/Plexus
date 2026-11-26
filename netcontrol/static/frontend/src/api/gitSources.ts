import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';
import { INTENDED_CONFIG_QUERY_ROOT } from './intendedConfig';

// Git data sources (admin only): repositories templates, playbooks and config
// contexts sync from. See docs/git-data-sources.md.

export type GitContentType = 'templates' | 'playbooks' | 'config_contexts';
export type GitSourceStatus = 'never' | 'syncing' | 'ok' | 'warning' | 'error';

export interface GitSyncWarning {
  path: string;
  message: string;
}

export interface GitSyncCounts {
  created: number;
  updated: number;
  unchanged: number;
  removed: number;
  detached: number;
}

export interface GitSyncSummary {
  commit: string;
  counts: Record<GitContentType, GitSyncCounts>;
  warnings: GitSyncWarning[];
}

export interface GitSource {
  id: number;
  name: string;
  remote_url: string;
  branch: string;
  credential_id: number | null;
  credential_name: string;
  provides: GitContentType[];
  sync_interval_minutes: number;
  enabled: boolean;
  status: GitSourceStatus | string;
  error: string;
  last_commit: string;
  last_attempt_at: string;
  last_synced_at: string;
  /** The newest successful sync's summary; `{}` before the first one. */
  summary: Partial<GitSyncSummary>;
  object_counts: Record<GitContentType, number>;
  created_at: string;
  updated_at: string;
  updated_by: string;
}

export interface GitSourceInput {
  name: string;
  remote_url: string;
  branch: string;
  credential_id: number | null;
  provides: GitContentType[];
  sync_interval_minutes: number;
  enabled: boolean;
}

export interface GitSyncResult {
  ok: boolean;
  source: GitSource;
  result: GitSyncSummary | null;
}

/** The ownership fields a template, playbook or config context carries. */
export interface GitOwnership {
  git_source_id?: number | null;
  git_source_name?: string | null;
  git_path?: string;
  git_commit?: string;
}

/** Whether a Git source owns the record (it is then read-only in Plexus). */
export function isGitOwned(record: GitOwnership): boolean {
  return record.git_source_id != null;
}

const KEY = ['git-sources'] as const;

export function useGitSources() {
  return useQuery<{ sources: GitSource[]; content_types: GitContentType[] }>({
    queryKey: KEY,
    queryFn: ({ signal }) => apiRequest('/git-sources', { signal }),
  });
}

export function useCreateGitSource() {
  const qc = useQueryClient();
  return useMutation<GitSource, Error, GitSourceInput>({
    mutationFn: (data) => apiRequest<GitSource>('/git-sources', { method: 'POST', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useUpdateGitSource() {
  const qc = useQueryClient();
  return useMutation<GitSource, Error, { id: number; data: GitSourceInput }>({
    mutationFn: ({ id, data }) => apiRequest<GitSource>(`/git-sources/${id}`, { method: 'PUT', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

/** A sync or a delete changes the templates, playbooks and contexts it owns. */
function invalidateOwned(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: KEY });
  qc.invalidateQueries({ queryKey: ['config-templates'] });
  qc.invalidateQueries({ queryKey: ['playbooks'] });
  qc.invalidateQueries({ queryKey: INTENDED_CONFIG_QUERY_ROOT });
}

export function useDeleteGitSource() {
  const qc = useQueryClient();
  return useMutation<{ ok: boolean; removed: number; detached: number }, Error, number>({
    mutationFn: (id) => apiRequest(`/git-sources/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateOwned(qc),
  });
}

export function useSyncGitSource() {
  const qc = useQueryClient();
  return useMutation<GitSyncResult, Error, number>({
    mutationFn: (id) => apiRequest<GitSyncResult>(`/git-sources/${id}/sync`, { method: 'POST' }),
    onSuccess: () => invalidateOwned(qc),
  });
}
