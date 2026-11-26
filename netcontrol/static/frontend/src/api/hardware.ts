/**
 * Hardware components of a device (chassis, stack members, supervisors, line
 * cards and other modules, power supplies, fans, transceivers) with their
 * serials, and the history of changes to them (installed, removed, replaced,
 * moved, revision changed). Read by SNMP every six hours and after module or
 * restart events; a refresh reads now. Reading needs the `inventory` feature,
 * a refresh `inventory.write`. Failures throw an Error with the server's
 * plain message.
 */
import { keepPreviousData, useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import type { ComponentStatus, HardwareCategory, HardwareEventType } from '@/lib/hardware';

import { queryString } from './client';
import { detailRequest } from './customData';

// ── Types ──────────────────────────────────────────────────────────────────

export type HardwareSource = 'snmp' | 'ssh';

export interface HardwareComponent {
  id: number;
  host_id: number;
  hostname: string;
  category: HardwareCategory;
  slot: string;
  name: string;
  description: string;
  model: string;
  serial: string;
  hardware_rev: string;
  firmware_rev: string;
  software_rev: string;
  status: ComponentStatus;
  source: HardwareSource;
  /** UTC "YYYY-MM-DD HH:MM:SS". */
  first_seen: string;
  last_seen: string;
  removed_at: string | null;
}

export interface HardwareEvent {
  id: number;
  host_id: number | null;
  hostname: string;
  occurred_at: string;
  event: HardwareEventType;
  category: string;
  slot: string;
  name: string;
  model: string;
  serial: string;
  previous_serial: string;
  previous_model: string;
  previous_slot: string;
  previous_host_id: number | null;
  previous_hostname: string;
  /** Field -> before / after; empty unless `event` is "changed". */
  changes: Record<string, { before: string; after: string }>;
  /** One plain sentence from the server. */
  detail: string;
}

export interface HostHardware {
  host_id: number;
  collected_at: string | null;
  source: HardwareSource | '';
  /** `never`: not read yet; `not_read`: the last read failed or is unsupported (see `message`). */
  state: 'ok' | 'never' | 'not_read';
  message: string;
  /** Removed components included. */
  components: HardwareComponent[];
}

export interface HardwareRefreshResult extends HostHardware {
  new_events: HardwareEvent[];
}

export interface HardwareEventPage {
  total: number;
  events: HardwareEvent[];
}

export interface HardwareComponentPage {
  total: number;
  components: HardwareComponent[];
}

export interface ComponentQuery {
  search?: string;
  category?: HardwareCategory | '';
  status?: ComponentStatus | '';
  group_id?: number | null;
  limit?: number;
  offset?: number;
}

export interface EventQuery {
  search?: string;
  /** One event type, or several separated by commas; empty for every type. */
  event?: string;
  host_id?: number | null;
  category?: HardwareCategory | '';
  limit?: number;
  offset?: number;
}

/** Events per request on the device page's history. */
export const HOST_EVENTS_PAGE_SIZE = 100;

// ── Query keys ─────────────────────────────────────────────────────────────

const ROOT = ['hardware'] as const;
export const HARDWARE_KEYS = {
  root: ROOT,
  host: (hostId: number) => [...ROOT, 'host', hostId] as const,
  hostEvents: (hostId: number) => [...ROOT, 'host-events', hostId] as const,
  components: (q: ComponentQuery) => [...ROOT, 'components', q] as const,
  events: (q: EventQuery) => [...ROOT, 'events', q] as const,
};

// ── Queries ────────────────────────────────────────────────────────────────

/** The components of one device, removed ones included. */
export function useHostHardware(hostId: number | null, enabled = true) {
  return useQuery<HostHardware>({
    queryKey: HARDWARE_KEYS.host(hostId ?? 0),
    queryFn: ({ signal }) => detailRequest<HostHardware>(`/hosts/${hostId}/hardware`, { signal }),
    enabled: enabled && hostId !== null,
  });
}

/** One device's hardware history, newest first, a page at a time ("Load more"). */
export function useHostHardwareEvents(hostId: number | null, enabled = true) {
  return useInfiniteQuery({
    queryKey: HARDWARE_KEYS.hostEvents(hostId ?? 0),
    queryFn: ({ pageParam, signal }) =>
      detailRequest<HardwareEventPage>(
        `/hosts/${hostId}/hardware/events${queryString({ limit: HOST_EVENTS_PAGE_SIZE, offset: pageParam })}`,
        { signal },
      ),
    initialPageParam: 0,
    getNextPageParam: (last, pages) => {
      const loaded = pages.reduce((n, p) => n + p.events.length, 0);
      return last.events.length > 0 && loaded < last.total ? loaded : undefined;
    },
    enabled: enabled && hostId !== null,
  });
}

/** Components across the fleet, one server page. */
export function useHardwareComponents(q: ComponentQuery) {
  return useQuery<HardwareComponentPage>({
    queryKey: HARDWARE_KEYS.components(q),
    queryFn: ({ signal }) => detailRequest<HardwareComponentPage>(`/hardware/components${queryString(q)}`, { signal }),
    placeholderData: keepPreviousData,
  });
}

/** Hardware changes across the fleet, newest first, one server page. */
export function useHardwareEvents(q: EventQuery) {
  return useQuery<HardwareEventPage>({
    queryKey: HARDWARE_KEYS.events(q),
    queryFn: ({ signal }) => detailRequest<HardwareEventPage>(`/hardware/events${queryString(q)}`, { signal }),
    placeholderData: keepPreviousData,
  });
}

// ── Mutations ──────────────────────────────────────────────────────────────

/** Read the device's hardware now. */
export function useRefreshHostHardware(hostId: number) {
  const qc = useQueryClient();
  return useMutation<HardwareRefreshResult, Error, void>({
    mutationFn: () => detailRequest<HardwareRefreshResult>(`/hosts/${hostId}/hardware/refresh`, { method: 'POST' }),
    onSuccess: (data) => {
      qc.setQueryData<HostHardware>(HARDWARE_KEYS.host(hostId), data);
      void qc.invalidateQueries({ queryKey: ROOT });
    },
  });
}

/** The fleet's components as CSV with the same filter (browser handles the download). */
export function hardwareExportUrl(q: Omit<ComponentQuery, 'limit' | 'offset'>): string {
  return `/api/hardware/components/export${queryString(q)}`;
}
