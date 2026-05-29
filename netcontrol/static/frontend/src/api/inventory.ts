/**
 * Inventory API - groups, hosts, SNMP profiles, discovery.
 *
 * Mirrors the legacy api.js inventory functions on top of the React-app
 * apiRequest wrapper. Reuses the lightweight `useInventoryGroups` /
 * `useCredentials` from compliance.ts but adds the richer types the
 * inventory page itself needs (model, serial_number, software_version, etc).
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest, getCsrfToken } from './client';

// ── Types ──────────────────────────────────────────────────────────────────

export interface InventoryHost {
  id: number;
  hostname: string;
  ip_address: string;
  device_type?: string | null;
  model?: string | null;
  serial_number?: string | null;
  software_version?: string | null;
  status?: string | null;
}

export interface InventoryGroupFull {
  id: number;
  name: string;
  description?: string | null;
  host_count?: number | null;
  hosts?: InventoryHost[];
}

export interface SnmpProfileV3 {
  username?: string;
  auth_protocol?: string;
  auth_password?: string;
  priv_protocol?: string;
  priv_password?: string;
}

export interface SnmpProfile {
  id: string;
  name: string;
  enabled: boolean;
  version: '2c' | '3' | string;
  community?: string;
  port?: number;
  timeout_seconds?: number;
  retries?: number;
  enable_inferred_topology?: boolean;
  v3?: SnmpProfileV3;
}

export interface SnmpProfileAssignment {
  group_id: number;
  snmp_profile_id: string;
}

export interface DiscoveredHost {
  hostname?: string;
  ip_address: string;
  device_type?: string;
  [key: string]: unknown;
}

export interface DiscoverySyncResult {
  scanned_hosts?: number;
  discovered_count?: number;
  discovered_hosts?: DiscoveredHost[];
  sync?: { added?: number; updated?: number; removed?: number };
}

export interface DiscoveryScanResult {
  scanned_hosts?: number;
  discovered_count?: number;
  discovered_hosts?: DiscoveredHost[];
}

export interface DiscoveryOptions {
  timeoutSeconds?: number;
  maxHosts?: number;
  deviceType?: string;
  hostnamePrefix?: string;
  useSnmp?: boolean;
  useIcmp?: boolean;
  removeAbsent?: boolean;
}

export interface ScanStreamEvent {
  type: 'start' | 'progress' | 'syncing' | 'done' | string;
  total?: number;
  scanned?: number;
  ip?: string;
  found?: boolean;
  host?: DiscoveredHost;
  discovered_hosts?: DiscoveredHost[];
  scanned_hosts?: number;
  discovered_count?: number;
  sync?: DiscoverySyncResult['sync'];
}

export interface SnmpTestResponse {
  success: boolean;
  error?: string;
  result?: {
    hostname?: string;
    ip_address?: string;
    device_type?: string;
    discovery?: {
      protocol?: string;
      vendor?: string;
      os?: string;
      sys_descr?: string;
    };
  };
}

export interface SerialFetchResult {
  serial_number: string;
}

export interface BulkSerialFetchResult {
  results: Array<{
    host_id: number;
    ok: boolean;
    serial_number?: string;
    error?: string;
  }>;
}

// ── Queries ────────────────────────────────────────────────────────────────

export function useInventoryGroupsFull(includeHosts = true) {
  return useQuery<InventoryGroupFull[]>({
    queryKey: ['inventory-groups-full', includeHosts],
    queryFn: () =>
      apiRequest(includeHosts ? '/inventory?include_hosts=true' : '/inventory'),
  });
}

export function useSnmpProfiles() {
  return useQuery<SnmpProfile[]>({
    queryKey: ['snmp-profiles'],
    queryFn: () => apiRequest('/admin/snmp-profiles'),
  });
}

export function useGroupSnmpAssignments(groupIds: number[]) {
  return useQuery<Record<number, string>>({
    queryKey: ['snmp-profile-assignments'],
    queryFn: async () => {
      const data = await apiRequest<{ assignments: SnmpProfileAssignment[] }>(
        '/inventory/snmp-profile-assignments',
      );
      const map: Record<number, string> = {};
      for (const a of data.assignments ?? []) {
        map[a.group_id] = a.snmp_profile_id || '';
      }
      for (const gid of groupIds) {
        if (!(gid in map)) map[gid] = '';
      }
      return map;
    },
    enabled: groupIds.length > 0,
  });
}

// ── Mutations: groups & hosts ──────────────────────────────────────────────

function invalidateInventory(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: ['inventory-groups-full'] });
  qc.invalidateQueries({ queryKey: ['inventory-groups'] });
}

export function useReorderInventoryGroups() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (orderedIds: number[]) =>
      apiRequest('/inventory/groups/reorder', {
        method: 'POST',
        body: { ordered_ids: orderedIds },
      }),
    onSuccess: () => invalidateInventory(qc),
  });
}

export function useCreateInventoryGroup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: { name: string; description?: string }) =>
      apiRequest<{ id: number; name: string }>('/inventory', {
        method: 'POST',
        body: input,
      }),
    onSuccess: () => invalidateInventory(qc),
  });
}

export function useUpdateInventoryGroup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      name,
      description,
    }: {
      id: number;
      name: string;
      description?: string;
    }) =>
      apiRequest(`/inventory/${id}`, {
        method: 'PUT',
        body: { name, description },
      }),
    onSuccess: () => invalidateInventory(qc),
  });
}

export function useDeleteInventoryGroup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/inventory/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateInventory(qc),
  });
}

export function useAddHost() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      groupId,
      hostname,
      ip_address,
      device_type,
    }: {
      groupId: number;
      hostname: string;
      ip_address: string;
      device_type: string;
    }) =>
      apiRequest(`/inventory/${groupId}/hosts`, {
        method: 'POST',
        body: { hostname, ip_address, device_type },
      }),
    onSuccess: () => invalidateInventory(qc),
  });
}

export function useUpdateHost() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      hostId,
      hostname,
      ip_address,
      device_type,
      group_id,
    }: {
      hostId: number;
      hostname: string;
      ip_address: string;
      device_type: string;
      group_id?: number;
    }) =>
      apiRequest(`/hosts/${hostId}`, {
        method: 'PUT',
        body: { hostname, ip_address, device_type, group_id },
      }),
    onSuccess: () => invalidateInventory(qc),
  });
}

export function useDeleteHost() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (hostId: number) =>
      apiRequest(`/hosts/${hostId}`, { method: 'DELETE' }),
    onSuccess: () => invalidateInventory(qc),
  });
}

export function useBulkDeleteHosts() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (hostIds: number[]) =>
      apiRequest('/hosts/bulk-delete', {
        method: 'POST',
        body: { host_ids: hostIds },
      }),
    onSuccess: () => invalidateInventory(qc),
  });
}

export function useMoveHosts() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      hostIds,
      targetGroupId,
    }: {
      hostIds: number[];
      targetGroupId: number;
    }) =>
      apiRequest('/hosts/move', {
        method: 'POST',
        body: { host_ids: hostIds, target_group_id: targetGroupId },
      }),
    onSuccess: () => invalidateInventory(qc),
  });
}

// ── Mutations: SNMP profiles & assignments ─────────────────────────────────

function invalidateSnmp(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: ['snmp-profiles'] });
  qc.invalidateQueries({ queryKey: ['snmp-profile-assignments'] });
}

export function useCreateSnmpProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: Partial<SnmpProfile>) =>
      apiRequest('/admin/snmp-profiles', { method: 'POST', body: payload }),
    onSuccess: () => invalidateSnmp(qc),
  });
}

export function useUpdateSnmpProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Partial<SnmpProfile> }) =>
      apiRequest(`/admin/snmp-profiles/${id}`, { method: 'PUT', body: payload }),
    onSuccess: () => invalidateSnmp(qc),
  });
}

export function useDeleteSnmpProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      apiRequest(`/admin/snmp-profiles/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateSnmp(qc),
  });
}

export function useAssignSnmpProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ groupId, profileId }: { groupId: number; profileId: string }) =>
      apiRequest(`/inventory/${groupId}/snmp-profile-assignment`, {
        method: 'PUT',
        body: { snmp_profile_id: profileId },
      }),
    onSuccess: () => invalidateSnmp(qc),
  });
}

// ── Discovery ──────────────────────────────────────────────────────────────

function discoveryBody(
  cidrs: string[],
  opts: DiscoveryOptions,
  includeRemoveAbsent = false,
) {
  return {
    cidrs,
    timeout_seconds: opts.timeoutSeconds,
    max_hosts: opts.maxHosts,
    device_type: opts.deviceType,
    hostname_prefix: opts.hostnamePrefix,
    use_snmp: opts.useSnmp !== false,
    use_icmp: opts.useIcmp !== false,
    ...(includeRemoveAbsent ? { remove_absent: !!opts.removeAbsent } : {}),
  };
}

export function useScanInventoryGroup() {
  return useMutation<
    DiscoveryScanResult,
    Error,
    { groupId: number; cidrs: string[]; opts: DiscoveryOptions }
  >({
    mutationFn: ({ groupId, cidrs, opts }) =>
      apiRequest(`/inventory/${groupId}/discovery/scan`, {
        method: 'POST',
        body: discoveryBody(cidrs, opts),
      }),
  });
}

export function useSyncInventoryGroup() {
  const qc = useQueryClient();
  return useMutation<
    DiscoverySyncResult,
    Error,
    { groupId: number; cidrs: string[]; opts: DiscoveryOptions }
  >({
    mutationFn: ({ groupId, cidrs, opts }) =>
      apiRequest(`/inventory/${groupId}/discovery/sync`, {
        method: 'POST',
        body: {
          ...discoveryBody(cidrs, opts),
          remove_absent: !!opts.removeAbsent,
        },
      }),
    onSuccess: () => invalidateInventory(qc),
  });
}

export function useOnboardDiscoveredHosts() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      groupId,
      hosts,
    }: {
      groupId: number;
      hosts: DiscoveredHost[];
    }) =>
      apiRequest<DiscoverySyncResult>(`/inventory/${groupId}/discovery/onboard`, {
        method: 'POST',
        body: { discovered_hosts: hosts },
      }),
    onSuccess: () => invalidateInventory(qc),
  });
}

export function useTestGroupSnmpProfile() {
  return useMutation<
    SnmpTestResponse,
    Error,
    { groupId: number; targetIp: string }
  >({
    mutationFn: ({ groupId, targetIp }) =>
      apiRequest(`/inventory/${groupId}/snmp-discovery-profile/test`, {
        method: 'POST',
        body: { target_ip: targetIp },
      }),
  });
}

// ── Streaming scan/sync (SSE-style line-delimited JSON) ───────────────────

/**
 * POSTs to an NDJSON streaming discovery endpoint and invokes `onEvent` for
 * each JSON line as it arrives, so callers can render live progress.
 * Shared by the scan and sync streams (identical wire format).
 */
async function streamDiscovery(
  path: string,
  cidrs: string[],
  opts: DiscoveryOptions,
  onEvent: (event: ScanStreamEvent) => void,
  signal?: AbortSignal,
  includeRemoveAbsent = false,
): Promise<void> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'text/event-stream, application/x-ndjson, application/json',
  };
  const csrf = getCsrfToken();
  if (csrf) headers['X-CSRF-Token'] = csrf;

  const res = await fetch(path, {
    method: 'POST',
    credentials: 'include',
    headers,
    body: JSON.stringify(discoveryBody(cidrs, opts, includeRemoveAbsent)),
    signal,
  });

  if (!res.ok || !res.body) {
    const text = await res.text().catch(() => '');
    throw new Error(text || `Discovery stream failed: ${res.status}`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  const flushLine = (raw: string) => {
    let line = raw.trim();
    if (!line) return;
    // Tolerate SSE-style "data: {...}" prefixes.
    if (line.startsWith('data:')) line = line.slice(5).trim();
    if (!line) return;
    try {
      const event = JSON.parse(line) as ScanStreamEvent;
      onEvent(event);
    } catch {
      // ignore non-JSON heartbeats
    }
  };

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let idx = buffer.indexOf('\n');
    while (idx !== -1) {
      const raw = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 1);
      flushLine(raw);
      idx = buffer.indexOf('\n');
    }
  }
  if (buffer.trim()) flushLine(buffer);
}

/**
 * Streams scan events from POST `/api/inventory/{id}/discovery/scan/stream`.
 */
export function streamScanInventoryGroup(
  groupId: number,
  cidrs: string[],
  opts: DiscoveryOptions,
  onEvent: (event: ScanStreamEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  return streamDiscovery(
    `/api/inventory/${groupId}/discovery/scan/stream`,
    cidrs,
    opts,
    onEvent,
    signal,
  );
}

/**
 * Streams sync events from POST `/api/inventory/{id}/discovery/sync/stream`:
 * per-host probe `progress`, a `syncing` event while reconciling with the
 * DB, then a `done` event carrying the add/update/remove counts.
 */
export function streamSyncInventoryGroup(
  groupId: number,
  cidrs: string[],
  opts: DiscoveryOptions,
  onEvent: (event: ScanStreamEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  return streamDiscovery(
    `/api/inventory/${groupId}/discovery/sync/stream`,
    cidrs,
    opts,
    onEvent,
    signal,
    true,
  );
}

// ── Serial number fetching ─────────────────────────────────────────────────

export function useFetchHostSerial() {
  const qc = useQueryClient();
  return useMutation<
    SerialFetchResult,
    Error,
    { hostId: number; credentialId: number }
  >({
    mutationFn: ({ hostId, credentialId }) =>
      apiRequest(`/hosts/${hostId}/fetch-serial`, {
        method: 'POST',
        body: { credential_id: credentialId },
      }),
    onSuccess: () => invalidateInventory(qc),
  });
}

export function useFetchGroupSerials() {
  const qc = useQueryClient();
  return useMutation<
    BulkSerialFetchResult,
    Error,
    { groupId: number; credentialId: number }
  >({
    mutationFn: ({ groupId, credentialId }) =>
      apiRequest(`/groups/${groupId}/fetch-serials`, {
        method: 'POST',
        body: { credential_id: credentialId },
      }),
    onSuccess: () => invalidateInventory(qc),
  });
}

// ── CSV export URL (browser handles download) ─────────────────────────────

export function inventoryCsvExportUrl(): string {
  return '/api/inventory/export/csv';
}
