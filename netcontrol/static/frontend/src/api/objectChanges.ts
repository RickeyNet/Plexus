import { keepPreviousData, useQuery } from '@tanstack/react-query';

import { apiRequest, queryString } from './client';

// ── Per-object change log (/api/changes, docs/change-log.md) ────────────────

export type ObjectChangeAction = 'create' | 'update' | 'delete';

export type ObjectChangeType =
  | 'host'
  | 'group'
  | 'prefix'
  | 'ip_address'
  | 'vlan'
  | 'vrf'
  | 'credential'
  | 'config_backup'
  | 'job';

/** One field of an update: its value before and after. */
export interface FieldChange {
  before: unknown;
  after: unknown;
}

export interface ObjectChange {
  id: number;
  object_type: ObjectChangeType | string;
  object_id: string;
  /** The object's name when the change happened (kept after a delete). */
  object_label: string;
  action: ObjectChangeAction | string;
  user: string;
  correlation_id: string;
  /** UTC "YYYY-MM-DD HH:MM:SS". */
  changed_at: string;
  /** The fields an update changed; empty for a create or delete. */
  changes: Record<string, FieldChange>;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
}

export interface ObjectChangePage {
  changes: ObjectChange[];
  total: number;
  limit: number;
  offset: number;
  /** The types this caller may read. */
  object_types: string[];
}

export interface ObjectChangeFilter {
  object_type?: string;
  object_id?: string;
  object_label?: string;
  user?: string;
  action?: string;
  since?: string;
  until?: string;
  limit?: number;
  offset?: number;
}

/** The change log, newest first, filtered and paged. */
export function useObjectChanges(filter: ObjectChangeFilter, enabled = true) {
  return useQuery<ObjectChangePage>({
    queryKey: ['object-changes', filter],
    queryFn: () => apiRequest(`/changes${queryString(filter)}`),
    placeholderData: keepPreviousData,
    enabled,
  });
}
