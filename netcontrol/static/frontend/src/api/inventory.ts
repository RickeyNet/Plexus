/**
 * Inventory API - groups, hosts, SNMP profiles, discovery.
 *
 * Mirrors the legacy api.js inventory functions on top of the React-app
 * apiRequest wrapper. Reuses the lightweight `useInventoryGroups` /
 * `useCredentials` from compliance.ts but adds the richer types the
 * inventory page itself needs (model, serial_number, software_version, etc).
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import type { HostNetworkFields } from '@/lib/networkObjects';

import { apiRequest, errorMessage, getCsrfToken } from './client';
import type { CustomValue, TagRef } from './customData';

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
  /** Explicit EC2 instance ID pinning this host on the Topology map ('' when unset). */
  aws_instance_id?: string | null;
  /** The host's VRF ('' for the global VRF); absent on rows of the all-groups listing. */
  vrf_name?: string | null;
  /** The host's VLAN id as text ('' when unset); absent on rows of the all-groups listing. */
  vlan_id?: string | null;
  /** The host's tags (inline from the listing). */
  tags?: TagRef[];
  /** The host's custom field values by field key (stored values only). */
  custom_fields?: Record<string, CustomValue>;
  /** Device model links (absent on rows from a server without the device model). */
  device_type_id?: number | null;
  role_id?: number | null;
  lifecycle_status_id?: number | null;
  site_id?: number | null;
  /** The tenant that owns the host. */
  tenant_id?: number | null;
  /** The region of the host's site and the regions above it, nearest first (empty: none). */
  region_ids?: number[];
  /** Rack, room or other place inside the site ('' when unset). */
  location_detail?: string | null;
  /** The linked hardware device type, for display. */
  hardware?: HostHardwareRef | null;
  role?: HostColorRef | null;
  lifecycle_status?: HostColorRef | null;
  site?: { id: number; name: string } | null;
  tenant?: { id: number; name: string } | null;
  /** The host's own SNMP profile ('' or absent: it uses its group's profile). */
  snmp_profile_id?: string;
  /**
   * 1 when an admin set or confirmed the host's address, 0 while it awaits
   * an admin's confirmation (no shared credential or SNMP secret is sent to
   * it, and it is not polled). Absent on rows from an older server.
   */
  address_confirmed?: number | boolean | null;
}

/** Whether a host's address awaits an admin's confirmation. */
export function addressAwaitingConfirmation(host: Pick<InventoryHost, 'address_confirmed'>): boolean {
  return host.address_confirmed === 0 || host.address_confirmed === false;
}

/** The ids of the hosts among `hosts` whose address awaits an admin's confirmation. */
export function awaitingHostIds(hosts: InventoryHost[]): number[] {
  return hosts.filter(addressAwaitingConfirmation).map((h) => h.id);
}

export interface HostHardwareRef {
  id: number;
  model: string;
  manufacturer_id: number;
  manufacturer: string;
}

/** A role or lifecycle status as shown on a host row. */
export interface HostColorRef {
  id: number;
  name: string;
  color: string;
}

/**
 * The device model values a host create or update may carry. A key left out
 * leaves the stored value alone; `null` clears it.
 */
export interface HostDeviceFields {
  device_type_id?: number | null;
  role_id?: number | null;
  lifecycle_status_id?: number | null;
  site_id?: number | null;
  tenant_id?: number | null;
  location_detail?: string;
}

export interface InventoryGroupFull {
  id: number;
  name: string;
  description?: string | null;
  /** The parent group; null for a top-level group. */
  parent_id?: number | null;
  /** The names from the top group down, joined with " / ". */
  path?: string | null;
  /** 0 for a top-level group, 1 for its sub-groups, and so on. */
  depth?: number | null;
  /** The group's direct hosts (sub-groups' hosts are not counted). */
  host_count?: number | null;
  hosts?: InventoryHost[];
  /** The group's tags (inline from the listing). */
  tags?: TagRef[];
  /** The group's custom field values by field key (stored values only). */
  custom_fields?: Record<string, CustomValue>;
}

/** Joins the names of a group path (mirrors the backend's GROUP_PATH_SEPARATOR). */
export const GROUP_PATH_SEPARATOR = ' / ';

/**
 * The text a group select or list shows for a group: its path from the top
 * (`Meraki / 1000 - HQ`), or its name when the listing has no path. The
 * `/api/inventory` listing is tree ordered, so paths read as a hierarchy.
 */
export function groupLabel(group: { name: string; path?: string | null }): string {
  return group.path || group.name;
}

export interface SnmpProfileV3 {
  username?: string;
  auth_protocol?: string;
  auth_password?: string;
  priv_protocol?: string;
  priv_password?: string;
}

/**
 * A named SNMP profile from GET /admin/snmp-profiles. Admins get the stored
 * profile (the editor needs it); other users get only id, name, enabled,
 * version, port and the has_* flags, never the community or v3 keys.
 */
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
  /** Public view only: whether the secret is set. */
  has_community?: boolean;
  has_v3_auth_password?: boolean;
  has_v3_priv_password?: boolean;
}

export interface SnmpProfileAssignment {
  group_id: number;
  snmp_profile_id: string;
}

export interface DiscoveredHost {
  hostname?: string;
  ip_address: string;
  device_type?: string;
  model?: string;
  software_version?: string;
  serial_number?: string;
  discovery?: {
    protocol?: string;
    /** "ssh" when device_type is the OS the device's show version reported. */
    device_type_source?: string;
    /** The show version read over SSH: ok, or the error on this host. */
    ssh?: { ok: boolean; error?: string };
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

/** How discovery read show version over SSH (model, serial, version, OS). */
export interface SshEnrichmentSummary {
  enabled: boolean;
  /** The credential's name; null when none was used. */
  credential: string | null;
  /** 'group': the credential the group remembers from its last explicit pick. */
  credential_source: 'explicit' | 'group' | 'service' | null;
  /** Why no host was read over SSH ('' when SSH ran). */
  skipped_reason: string;
  /** Why the group's remembered credential was not used ('' when it was, or there is none). */
  note?: string;
  attempted?: number;
  enriched?: number;
  failed?: number;
  failures?: { ip_address: string; error: string }[];
}

/** How many scan targets were probed without the group's SNMP settings, and why ('' when none). */
export interface SnmpWithheldSummary {
  count: number;
  reason: string;
}

export interface DiscoverySyncResult {
  scanned_hosts?: number;
  discovered_count?: number;
  discovered_hosts?: DiscoveredHost[];
  sync?: { added?: number; updated?: number; removed?: number };
  ssh_enrichment?: SshEnrichmentSummary;
  snmp_withheld?: SnmpWithheldSummary;
}

export interface DiscoveryScanResult {
  scanned_hosts?: number;
  discovered_count?: number;
  discovered_hosts?: DiscoveredHost[];
  ssh_enrichment?: SshEnrichmentSummary;
  snmp_withheld?: SnmpWithheldSummary;
}

export interface DiscoveryOptions {
  timeoutSeconds?: number;
  maxHosts?: number;
  deviceType?: string;
  hostnamePrefix?: string;
  useSnmp?: boolean;
  useIcmp?: boolean;
  /** Read model, serial, version and OS over SSH show version (default on). */
  useSsh?: boolean;
  /**
   * The credential for SSH, remembered for the group; null/omitted: the
   * group's remembered credential, else the Plexus service credential.
   */
  credentialId?: number | null;
  /** Without credentialId: the Plexus service credential, and the group forgets its own. */
  useServiceCredential?: boolean;
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
  ssh_enrichment?: SshEnrichmentSummary;
  snmp_withheld?: SnmpWithheldSummary;
}

/** The credential discovery uses for SSH by default. */
export interface DiscoverySshDefaults {
  service_credential: boolean;
  service_credential_id: number | null;
  service_credential_name: string | null;
  /** The credential the group's discovery remembers (group request only; null: none). */
  group_credential_id?: number | null;
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
  /** Hardware components stored from `show inventory`; 0 when the platform has none. */
  components?: number;
}

export interface BulkSerialFetchResult {
  results: Array<{
    host_id: number;
    ok: boolean;
    serial_number?: string;
    error?: string;
    components?: number;
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

export function useSnmpProfiles(enabled = true) {
  return useQuery<SnmpProfile[]>({
    queryKey: ['snmp-profiles'],
    queryFn: () => apiRequest('/admin/snmp-profiles'),
    enabled,
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

/** Refetches both inventory group listings (full and light). */
export function invalidateInventory(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: ['inventory-groups-full'] });
  qc.invalidateQueries({ queryKey: ['inventory-groups'] });
}

/** The query key root of the device model catalogues (api/deviceModel). */
export const DEVICE_MODEL_QUERY_ROOT = ['device-model'] as const;

/**
 * After a host is added, changed or deleted: the inventory listings, and the
 * host counts of the device model catalogues and of the sites.
 */
function invalidateHosts(qc: ReturnType<typeof useQueryClient>) {
  invalidateInventory(qc);
  qc.invalidateQueries({ queryKey: DEVICE_MODEL_QUERY_ROOT });
  qc.invalidateQueries({ queryKey: ['geo', 'sites'] });
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
    mutationFn: (input: { name: string; description?: string; parent_id?: number | null }) =>
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
      parent_id,
    }: {
      id: number;
      name: string;
      description?: string;
      /** The new parent (null: top level); omitted leaves it unchanged. */
      parent_id?: number | null;
    }) =>
      apiRequest(`/inventory/${id}`, {
        method: 'PUT',
        body: { name, description, ...(parent_id !== undefined ? { parent_id } : {}) },
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
      aws_instance_id,
      snmp_profile_id,
      device,
      network,
    }: {
      groupId: number;
      hostname: string;
      ip_address: string;
      device_type: string;
      /** Optional EC2 instance ID ('' or omitted leaves it unset). */
      aws_instance_id?: string;
      /** The host's own SNMP profile ('' or omitted: it uses its group's). */
      snmp_profile_id?: string;
      /** Device model values to store with the host. */
      device?: HostDeviceFields;
      /** The host's VRF and VLAN id (omitted keys stay unset). */
      network?: HostNetworkFields;
    }) =>
      apiRequest<{ id: number }>(`/inventory/${groupId}/hosts`, {
        method: 'POST',
        body: {
          hostname,
          ip_address,
          device_type,
          ...(aws_instance_id !== undefined ? { aws_instance_id } : {}),
          ...(snmp_profile_id !== undefined ? { snmp_profile_id } : {}),
          ...device,
          ...network,
        },
      }),
    onSuccess: () => invalidateHosts(qc),
  });
}

/**
 * One host of a bulk add (the body of a single add), with its group: by id,
 * by its path from the top (`['Meraki', 'HQ']`; each missing level is
 * created), or by the name of a top-level group (created when missing). At
 * most one; none uses the body's `group_id`.
 */
export interface BulkHostInput {
  hostname: string;
  ip_address: string;
  device_type: string;
  group_id?: number;
  group_path?: string[];
  group_name?: string;
  /** The device's serial: matched against inventory, and stored on the new host. */
  serial_number?: string;
  /** The EC2 instance the device is: matched against inventory, and stored on the new host. */
  aws_instance_id?: string;
}

/** Body of POST `/api/inventory/hosts/bulk`. */
export interface BulkAddHostsRequest {
  hosts: BulkHostInput[];
  /** The group of hosts that name none. */
  group_id?: number;
}

/** Response of POST `/api/inventory/hosts/bulk`. */
export interface BulkAddHostsResult {
  added: {
    id: number;
    hostname: string;
    ip_address: string;
    group_id: number;
    /** The group's own name (the leaf). */
    group_name: string;
    /** The group's path from the top, joined with " / ". */
    group_path: string;
  }[];
  /**
   * Devices already in inventory (matched by AWS instance, serial, IP or
   * interface address, or hostname): the host (and its group) it already is.
   */
  skipped: {
    hostname: string;
    ip_address: string;
    reason: string;
    host_id: number | null;
    group_id: number | null;
  }[];
  errors: { hostname: string; ip_address: string; error: string }[];
  /** Every group (each level of a path) the request created, parents first. */
  groups_created: { id: number; name: string; parent_id: number | null; path: string }[];
}

/** The most hosts one bulk add request takes (mirrors the backend's BULK_ADD_MAX_HOSTS). */
export const BULK_ADD_MAX_HOSTS = 500;

/** A bulk add body split into requests of at most `size` hosts, each with the body's `group_id`. */
export function chunkBulkAddBody(body: BulkAddHostsRequest, size = BULK_ADD_MAX_HOSTS): BulkAddHostsRequest[] {
  const chunks: BulkAddHostsRequest[] = [];
  for (let start = 0; start < body.hosts.length; start += size) {
    chunks.push({ ...body, hosts: body.hosts.slice(start, start + size) });
  }
  return chunks;
}

/** The results of two bulk add requests as one. */
export function mergeBulkAddResults(a: BulkAddHostsResult, b: BulkAddHostsResult): BulkAddHostsResult {
  return {
    added: [...a.added, ...b.added],
    skipped: [...a.skipped, ...b.skipped],
    errors: [...a.errors, ...b.errors],
    groups_created: [...a.groups_created, ...b.groups_created],
  };
}

/** What a chunked bulk add did. */
export interface BulkAddRun {
  /** The merged result of every request that completed. */
  result: BulkAddHostsResult;
  /** How many hosts of the body, from the start, were sent and answered. */
  attempted: number;
  total: number;
  /** Stopped on request before every host was sent. */
  stopped: boolean;
  /** The message of the request that failed; the hosts from it on were not added. */
  error: string | null;
}

export interface BulkAddOptions {
  /** Called after each request with how many hosts have been answered. */
  onProgress?: (done: number, total: number) => void;
  /** Checked before each request; true stops before sending it. */
  shouldStop?: () => boolean;
}

const EMPTY_BULK_RESULT: BulkAddHostsResult = { added: [], skipped: [], errors: [], groups_created: [] };

/**
 * Add any number of hosts: the body is sent as requests of at most
 * BULK_ADD_MAX_HOSTS hosts, one after another (each sees the hosts the
 * previous ones added, so a device in two requests is added once). A failed
 * request ends the run with what the earlier ones did.
 */
export async function bulkAddHostsInChunks(
  body: BulkAddHostsRequest,
  { onProgress, shouldStop }: BulkAddOptions = {},
  send: (chunk: BulkAddHostsRequest) => Promise<BulkAddHostsResult> = (chunk) =>
    apiRequest<BulkAddHostsResult>('/inventory/hosts/bulk', { method: 'POST', body: chunk }),
): Promise<BulkAddRun> {
  const total = body.hosts.length;
  let result = EMPTY_BULK_RESULT;
  let attempted = 0;
  for (const chunk of chunkBulkAddBody(body)) {
    if (shouldStop?.()) return { result, attempted, total, stopped: true, error: null };
    try {
      result = mergeBulkAddResults(result, await send(chunk));
    } catch (e) {
      return { result, attempted, total, stopped: false, error: (e as Error).message };
    }
    attempted += chunk.hosts.length;
    onProgress?.(attempted, total);
  }
  return { result, attempted, total, stopped: false, error: null };
}

/**
 * Add many hosts, each to the group its entry (or the body) names, in
 * requests of BULK_ADD_MAX_HOSTS (see `bulkAddHostsInChunks`). Inventory and
 * the map are refreshed once, when the run ends.
 */
export function useBulkAddHosts() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ body, ...options }: { body: BulkAddHostsRequest } & BulkAddOptions) =>
      bulkAddHostsInChunks(body, options),
    onSettled: () => {
      // Hosts and possibly new groups (both group lists).
      invalidateInventory(qc);
      // Added hosts become inventory nodes on the map.
      qc.invalidateQueries({ queryKey: ['topology'] });
    },
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
      aws_instance_id,
      snmp_profile_id,
      device,
      network,
    }: {
      hostId: number;
      hostname: string;
      ip_address: string;
      device_type: string;
      group_id?: number;
      /** EC2 instance ID; '' clears it, omitted leaves it unchanged. */
      aws_instance_id?: string;
      /** The host's own SNMP profile; '' clears it (back to the group's), omitted leaves it unchanged. */
      snmp_profile_id?: string;
      /** Changed device model values only: setting a device type or role locks it against discovery. */
      device?: HostDeviceFields;
      /** VRF and VLAN id; with neither key the stored values stay (build it with `hostNetworkBody`). */
      network?: HostNetworkFields;
    }) =>
      apiRequest(`/hosts/${hostId}`, {
        method: 'PUT',
        body: {
          hostname,
          ip_address,
          device_type,
          group_id,
          ...(aws_instance_id !== undefined ? { aws_instance_id } : {}),
          ...(snmp_profile_id !== undefined ? { snmp_profile_id } : {}),
          ...device,
          ...network,
        },
      }),
    onSuccess: () => invalidateHosts(qc),
  });
}

export function useDeleteHost() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (hostId: number) =>
      apiRequest(`/hosts/${hostId}`, { method: 'DELETE' }),
    onSuccess: () => invalidateHosts(qc),
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
    onSuccess: () => invalidateHosts(qc),
  });
}

export interface ConfirmHostAddressesResult {
  ok: boolean;
  /** The hosts whose address was awaiting confirmation and now is confirmed. */
  confirmed: number[];
  already_confirmed: number[];
}

/**
 * Admin only: confirm the addresses of `hostIds` and/or every host of
 * `groupId`, so the service credential and shared SNMP secrets may go to them.
 */
export function useConfirmHostAddresses() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ hostIds, groupId }: { hostIds?: number[]; groupId?: number }) =>
      apiRequest<ConfirmHostAddressesResult>('/admin/hosts/confirm-address', {
        method: 'POST',
        body: { host_ids: hostIds ?? [], ...(groupId !== undefined ? { group_id: groupId } : {}) },
      }),
    onSuccess: () => invalidateHosts(qc),
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

/** Gives the hosts their own SNMP profile; '' puts them back on their group's. */
export function useSetHostsSnmpProfile() {
  const qc = useQueryClient();
  return useMutation<
    { ok: boolean; updated: number },
    Error,
    { hostIds: number[]; profileId: string }
  >({
    mutationFn: ({ hostIds, profileId }) =>
      apiRequest('/hosts/snmp-profile', {
        method: 'POST',
        body: { host_ids: hostIds, snmp_profile_id: profileId },
      }),
    // The profile id rides on the host rows.
    onSuccess: () => invalidateInventory(qc),
  });
}

/** Tests the host's saved effective profile (its own, else its group's) against its IP. */
export function useTestHostSnmpProfile() {
  return useMutation<SnmpTestResponse, Error, { hostId: number }>({
    mutationFn: ({ hostId }) =>
      apiRequest(`/hosts/${hostId}/snmp-profile/test`, { method: 'POST' }),
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
    use_ssh: opts.useSsh !== false,
    credential_id: opts.credentialId ?? null,
    use_service_credential: !!opts.useServiceCredential,
    ...(includeRemoveAbsent ? { remove_absent: !!opts.removeAbsent } : {}),
  };
}

/** The SSH defaults, with the credential `groupId`'s discovery remembers when given. */
export function useDiscoverySshDefaults(groupId?: number | null) {
  return useQuery<DiscoverySshDefaults>({
    queryKey: ['inventory', 'discovery', 'ssh-defaults', groupId ?? null],
    queryFn: () =>
      apiRequest(
        groupId
          ? `/inventory/${groupId}/discovery/ssh-defaults`
          : '/inventory/discovery/ssh-defaults',
      ),
  });
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

/**
 * What changes when the server stored what a device reports (a discovery
 * sync or onboard, a verified upgrade): the hosts (model, software
 * version, serial) and groups, the inventory nodes on the map, and the
 * software tracker, which the server refreshes when the hosts are stored.
 */
export function invalidateHostFacts(qc: ReturnType<typeof useQueryClient>) {
  invalidateInventory(qc);
  qc.invalidateQueries({ queryKey: ['topology'] });
  qc.invalidateQueries({ queryKey: ['software-overview'] });
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
    onSuccess: () => invalidateHostFacts(qc),
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
    // A refusal (e.g. 403 on the service credential) is a JSON error body:
    // show its message, not the raw JSON.
    let message: string | null = null;
    try {
      message = errorMessage(JSON.parse(text));
    } catch {
      // Not JSON (a proxy error page): the text as is.
    }
    throw new Error(message || text || `Discovery stream failed: ${res.status}`);
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
 * DB, then a `done` event carrying the add/update/remove counts. However
 * the stream ends, the queries a sync changes are refetched through `qc`
 * (a stream that fails or is aborted may have stored part of the sync).
 */
export async function streamSyncInventoryGroup(
  qc: ReturnType<typeof useQueryClient>,
  groupId: number,
  cidrs: string[],
  opts: DiscoveryOptions,
  onEvent: (event: ScanStreamEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  try {
    await streamDiscovery(
      `/api/inventory/${groupId}/discovery/sync/stream`,
      cidrs,
      opts,
      onEvent,
      signal,
      true,
    );
  } finally {
    invalidateHostFacts(qc);
  }
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
    onSuccess: () => {
      invalidateInventory(qc);
      // The fetch also stores each module's serial (api/hardware).
      void qc.invalidateQueries({ queryKey: ['hardware'] });
    },
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
    onSuccess: () => {
      invalidateInventory(qc);
      // The fetch also stores each module's serial (api/hardware).
      void qc.invalidateQueries({ queryKey: ['hardware'] });
    },
  });
}

// ── CSV export URL (browser handles download) ─────────────────────────────

export function inventoryCsvExportUrl(): string {
  return '/api/inventory/export/csv';
}

/** The hosts of the CSV export as YAML (bulk import reads either back). */
export function inventoryYamlExportUrl(): string {
  return '/api/inventory/export/yaml';
}
