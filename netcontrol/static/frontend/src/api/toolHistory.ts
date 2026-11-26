import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

/** The tools whose last runs Plexus keeps per user (`/api/topology/history/{kind}`). */
export type ToolKind = 'path' | 'reachability' | 'summarize';

/** One run of a tool's history: its inputs as the page sent them. */
export interface ToolHistoryEntry<T> {
  id: number;
  data: T;
  /** UTC `YYYY-MM-DD HH:MM:SS`. */
  used_at: string;
}

interface ToolHistoryList<T> {
  entries: ToolHistoryEntry<T>[];
  limit: number;
}

const key = (kind: ToolKind) => ['tool-history', kind];

export function useToolHistory<T>(kind: ToolKind, enabled = true) {
  return useQuery({
    queryKey: key(kind),
    queryFn: ({ signal }) => apiRequest<ToolHistoryList<T>>(`/topology/history/${kind}`, { signal }),
    enabled,
    staleTime: 30_000,
  });
}

/**
 * Records a run at the top of the history. `key` says what makes two runs
 * the same (default: the inputs themselves).
 */
export function useRecordToolHistory<T extends object>(kind: ToolKind) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (entry: { data: T; key?: string }) =>
      apiRequest<ToolHistoryEntry<T>>(`/topology/history/${kind}`, { method: 'POST', body: entry }),
    onSuccess: () => qc.invalidateQueries({ queryKey: key(kind) }),
  });
}

/** Forgets one run (`id`), or every run of the tool (`null`). */
export function useDeleteToolHistory(kind: ToolKind) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number | null) =>
      apiRequest(id === null ? `/topology/history/${kind}` : `/topology/history/${kind}/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: key(kind) }),
  });
}
