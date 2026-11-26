/**
 * Dynamic groups: named, saved host filters (/api/dynamic-groups) that
 * resolve to the hosts matching them whenever they are used. Members and
 * previews are resolved on the server within the caller's object scope.
 */
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import type { DynamicGroupFilter } from '@/lib/dynamicGroupFilter';

import { detailRequest } from './customData';

export interface DynamicGroup {
  id: number;
  name: string;
  description: string;
  object_type: 'host';
  filter: DynamicGroupFilter;
  created_by?: string;
  created_at?: string;
  updated_at?: string;
  updated_by?: string;
  /** Hosts matching now, among those you may read (list and detail only). */
  member_count?: number;
}

export interface DynamicGroupMember {
  id: number;
  hostname: string;
  ip_address: string;
  device_type: string | null;
  status: string | null;
  group_id: number | null;
  group_name: string | null;
  model: string | null;
  software_version: string | null;
}

export interface DynamicGroupMembers {
  count: number;
  hosts: DynamicGroupMember[];
  truncated: boolean;
}

export interface DynamicGroupInput {
  name: string;
  description: string;
  filter: DynamicGroupFilter;
}

const ROOT = ['dynamic-groups'] as const;

export function useDynamicGroups(enabled = true) {
  return useQuery<DynamicGroup[]>({
    queryKey: ROOT,
    queryFn: ({ signal }) => detailRequest('/dynamic-groups', { signal }),
    enabled,
  });
}

export function useDynamicGroupMembers(id: number | null) {
  return useQuery<DynamicGroupMembers>({
    queryKey: [...ROOT, id, 'members'],
    queryFn: ({ signal }) => detailRequest(`/dynamic-groups/${id}/members`, { signal }),
    enabled: id != null,
  });
}

/**
 * The hosts an unsaved filter matches. `filterKey` is the serialised filter
 * (null: no preview); previous results stay on screen while the next loads.
 */
export function useDynamicGroupPreview(filter: DynamicGroupFilter | null, filterKey: string | null) {
  return useQuery<DynamicGroupMembers>({
    queryKey: [...ROOT, 'preview', filterKey],
    queryFn: ({ signal }) => detailRequest('/dynamic-groups/preview', { method: 'POST', body: { filter }, signal }),
    enabled: filter != null && filterKey != null,
    placeholderData: keepPreviousData,
    retry: false,
  });
}

export function useSaveDynamicGroup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, input }: { id: number | null; input: DynamicGroupInput }) =>
      id == null
        ? detailRequest<DynamicGroup>('/dynamic-groups', { method: 'POST', body: input })
        : detailRequest<DynamicGroup>(`/dynamic-groups/${id}`, { method: 'PUT', body: input }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ROOT }),
  });
}

export function useDeleteDynamicGroup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => detailRequest(`/dynamic-groups/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ROOT }),
  });
}
