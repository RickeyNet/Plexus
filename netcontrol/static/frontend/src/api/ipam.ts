/**
 * IPAM API - overview, subnet drilldown, external sources, reconciliation,
 * DHCP server integration. Mirrors the legacy api.js IPAM/DHCP functions.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

// ── Types ──────────────────────────────────────────────────────────────────

export interface IpamSummary {
  inventory_host_count?: number;
  total_subnets?: number;
  cloud_subnets?: number;
  external_subnets?: number;
  duplicate_ip_count?: number;
  inventory_subnets?: number;
  local_subnets?: number;
  external_allocation_count?: number;
  exact_source_overlap_count?: number;
}

export interface IpamSubnet {
  subnet: string;
  version?: number;
  prefix_length?: number;
  total_addresses?: number;
  available_address_count?: number;
  allocated_address_count?: number;
  reserved_address_count?: number;
  utilization_pct?: number;
  group_names?: string[];
  source_types?: string[];
  external_source_names_preview?: string[];
  hostnames_preview?: string[];
  cloud_resource_names_preview?: string[];
  available_preview?: string[];
  host_preview_truncated?: number;
  cloud_preview_truncated?: number;
  external_source_preview_truncated?: number;
  vrf_name?: string | null;
  vlan_ids?: Array<string | number>;
}

export interface IpamDuplicateHost {
  hostname?: string;
  group_name?: string;
  status?: string;
}

export interface IpamDuplicate {
  ip_address: string;
  host_count?: number;
  vrf_name?: string | null;
  hosts?: IpamDuplicateHost[];
}

export interface IpamOverview {
  summary?: IpamSummary;
  subnets?: IpamSubnet[];
  duplicate_ips?: IpamDuplicate[];
}

export interface IpamReservation {
  id: number;
  start_ip?: string;
  end_ip?: string;
  kind?: string;
  reason?: string;
  address_count?: number;
}

export interface IpamAllocation {
  allocation_id?: number;
  ip_address?: string;
  hostname?: string;
  dns_name?: string;
  description?: string;
  group_name?: string;
  source_type?: string;
  source_name?: string;
  status?: string;
  is_duplicate?: boolean;
  is_reserved?: boolean;
}

export interface IpamSubnetDetailSummary {
  total_addresses?: number;
  usable_address_count?: number;
  available_address_count?: number;
  allocated_address_count?: number;
  reserved_address_count?: number;
  utilization_pct?: number;
}

export interface IpamSubnetDetail {
  subnet?: string;
  summary?: IpamSubnetDetailSummary;
  reservations?: IpamReservation[];
  allocations?: IpamAllocation[];
  cloud_resources?: Array<{
    provider?: string;
    name?: string;
    resource_type?: string;
    account_name?: string;
  }>;
  external_prefixes?: Array<{
    source_name?: string;
    provider?: string;
    description?: string;
    status?: string;
  }>;
  available_preview?: string[];
}

export interface IpamProvider {
  id: string;
  name: string;
}

export interface IpamSource {
  id: number;
  name: string;
  provider: string;
  base_url: string;
  auth_type?: string;
  sync_scope?: string;
  notes?: string;
  enabled: boolean;
  push_enabled?: boolean;
  verify_tls?: boolean;
  last_sync_status?: string;
  last_sync_at?: string;
  last_sync_message?: string;
  prefix_count?: number;
  allocation_count?: number;
}

export interface IpamSyncConfig {
  enabled: boolean;
  interval_seconds: number;
}

export interface ReconcileRun {
  id: number;
  source_id: number;
  status: string;
  started_at?: string;
  diff_count?: number;
  resolved_count?: number;
}

export interface ReconcileDiff {
  id: number;
  source_id: number;
  address: string;
  drift_type: string;
  plexus_state?: { hostname?: string };
  ipam_state?: { dns_name?: string; status?: string };
}

export interface DhcpProvider {
  id: string;
  name: string;
}

export interface DhcpServer {
  id: number;
  name: string;
  provider: string;
  base_url?: string;
  auth_type?: string;
  notes?: string;
  enabled: boolean;
  verify_tls?: boolean;
  last_sync_status?: string;
  last_sync_at?: string;
  last_sync_message?: string;
  scope_count?: number;
  lease_count?: number;
}

export interface DhcpScopeAlert {
  subnet: string;
  name?: string;
  used_addresses: number;
  total_addresses: number;
  utilization_pct: number;
  exhausted?: boolean;
}

export interface DhcpExhaustion {
  exhausted: DhcpScopeAlert[];
  near_exhaustion: DhcpScopeAlert[];
  threshold_pct: number;
}

export interface DhcpUnknownLease {
  address: string;
  mac_address?: string;
  hostname?: string;
  scope_subnet?: string;
}

export interface DhcpCorrelation {
  totals: { known: number; unknown: number };
  known: unknown[];
  unknown: DhcpUnknownLease[];
}

// ── Query keys ─────────────────────────────────────────────────────────────

const KEYS = {
  overview: (groupId: number | null, includeCloud: boolean) =>
    ['ipam-overview', groupId ?? 'all', includeCloud] as const,
  subnetDetail: (subnet: string, groupId: number | null, includeCloud: boolean) =>
    ['ipam-subnet-detail', subnet, groupId ?? 'all', includeCloud] as const,
  providers: ['ipam-providers'] as const,
  sources: ['ipam-sources'] as const,
  syncConfig: ['ipam-sync-config'] as const,
  reconcileRuns: ['ipam-reconcile-runs'] as const,
  reconcileDiffs: ['ipam-reconcile-diffs'] as const,
  dhcpProviders: ['dhcp-providers'] as const,
  dhcpServers: ['dhcp-servers'] as const,
  dhcpExhaustion: ['dhcp-exhaustion'] as const,
  dhcpCorrelation: ['dhcp-correlation'] as const,
};

function invalidateOverview(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: ['ipam-overview'] });
  qc.invalidateQueries({ queryKey: ['ipam-subnet-detail'] });
}

function invalidateSources(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: KEYS.sources });
}

function invalidateReconcile(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: KEYS.reconcileRuns });
  qc.invalidateQueries({ queryKey: KEYS.reconcileDiffs });
}

function invalidateDhcp(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: KEYS.dhcpServers });
  qc.invalidateQueries({ queryKey: KEYS.dhcpExhaustion });
  qc.invalidateQueries({ queryKey: KEYS.dhcpCorrelation });
}

// ── Queries ────────────────────────────────────────────────────────────────

export function useIpamOverview(groupId: number | null, includeCloud: boolean) {
  return useQuery<IpamOverview>({
    queryKey: KEYS.overview(groupId, includeCloud),
    queryFn: () => {
      const params: Record<string, string> = {};
      if (groupId) params.group_id = String(groupId);
      if (!includeCloud) params.include_cloud = 'false';
      const qs = new URLSearchParams(params).toString();
      return apiRequest(`/ipam/overview${qs ? `?${qs}` : ''}`);
    },
  });
}

export function useIpamSubnetDetail(
  subnet: string | null,
  groupId: number | null,
  includeCloud: boolean,
) {
  return useQuery<IpamSubnetDetail>({
    queryKey: KEYS.subnetDetail(subnet ?? '', groupId, includeCloud),
    queryFn: () => {
      const params: Record<string, string> = {};
      if (groupId) params.group_id = String(groupId);
      if (!includeCloud) params.include_cloud = 'false';
      const qs = new URLSearchParams(params).toString();
      return apiRequest(
        `/ipam/subnets/${encodeURIComponent(subnet!)}${qs ? `?${qs}` : ''}`,
      );
    },
    enabled: !!subnet,
  });
}

export function useIpamProviders() {
  return useQuery<{ providers: IpamProvider[] }>({
    queryKey: KEYS.providers,
    queryFn: () => apiRequest('/ipam/providers'),
  });
}

export function useIpamSources() {
  return useQuery<{ sources: IpamSource[] }>({
    queryKey: KEYS.sources,
    queryFn: () => apiRequest('/ipam/sources'),
  });
}

export function useIpamSyncConfig() {
  return useQuery<{ config: IpamSyncConfig }>({
    queryKey: KEYS.syncConfig,
    queryFn: () => apiRequest('/ipam/sync-config'),
  });
}

export function useReconcileRuns() {
  return useQuery<{ runs: ReconcileRun[] }>({
    queryKey: KEYS.reconcileRuns,
    queryFn: () => apiRequest('/ipam/reconciliation/runs?limit=25'),
  });
}

export function useReconcileDiffs() {
  return useQuery<{ diffs: ReconcileDiff[] }>({
    queryKey: KEYS.reconcileDiffs,
    queryFn: () =>
      apiRequest('/ipam/reconciliation/diffs?open_only=true&limit=200'),
  });
}

export function useDhcpProviders() {
  return useQuery<{ providers: DhcpProvider[] }>({
    queryKey: KEYS.dhcpProviders,
    queryFn: () => apiRequest('/dhcp/providers'),
  });
}

export function useDhcpServers() {
  return useQuery<{ servers: DhcpServer[] }>({
    queryKey: KEYS.dhcpServers,
    queryFn: () => apiRequest('/dhcp/servers'),
  });
}

export function useDhcpExhaustion() {
  return useQuery<DhcpExhaustion>({
    queryKey: KEYS.dhcpExhaustion,
    queryFn: () => apiRequest('/dhcp/exhaustion'),
  });
}

export function useDhcpCorrelation() {
  return useQuery<DhcpCorrelation>({
    queryKey: KEYS.dhcpCorrelation,
    queryFn: () => apiRequest('/dhcp/correlation?limit=1000'),
  });
}

// ── IPAM mutations ─────────────────────────────────────────────────────────

export interface IpamSourcePayload {
  provider: string;
  name: string;
  base_url: string;
  auth_type: string;
  auth_config?: Record<string, string>;
  sync_scope?: string;
  notes?: string;
  enabled: boolean;
  push_enabled: boolean;
  verify_tls: boolean;
}

export function useCreateIpamSource() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: IpamSourcePayload) =>
      apiRequest('/ipam/sources', { method: 'POST', body: payload }),
    onSuccess: () => invalidateSources(qc),
  });
}

export function useUpdateIpamSource() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, payload }: { id: number; payload: IpamSourcePayload }) =>
      apiRequest(`/ipam/sources/${id}`, { method: 'PUT', body: payload }),
    onSuccess: () => invalidateSources(qc),
  });
}

export function useDeleteIpamSource() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/ipam/sources/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      invalidateSources(qc);
      invalidateOverview(qc);
    },
  });
}

export function useSyncIpamSource() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/ipam/sources/${id}/sync`, { method: 'POST' }),
    onSuccess: () => {
      invalidateSources(qc);
      invalidateOverview(qc);
    },
  });
}

export function useRunReconcile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest<{ summary?: { diff_count?: number } }>(
        `/ipam/sources/${id}/reconcile`,
        { method: 'POST' },
      ),
    onSuccess: () => invalidateReconcile(qc),
  });
}

export function useResolveDiff() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      diffId,
      resolution,
      note = '',
    }: {
      diffId: number;
      resolution: 'accept_plexus' | 'accept_ipam' | 'ignored';
      note?: string;
    }) =>
      apiRequest(`/ipam/reconciliation/diffs/${diffId}/resolve`, {
        method: 'POST',
        body: { resolution, note },
      }),
    onSuccess: () => invalidateReconcile(qc),
  });
}

export function useUpdateIpamSyncConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: { enabled: boolean; interval_seconds: number }) =>
      apiRequest<{ config: IpamSyncConfig }>('/ipam/sync-config', {
        method: 'PUT',
        body: payload,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEYS.syncConfig }),
  });
}

export function useCreateIpamPrefix() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: { subnet: string; description?: string; vrf?: string }) =>
      apiRequest('/ipam/prefixes', { method: 'POST', body: payload }),
    onSuccess: () => invalidateOverview(qc),
  });
}

export function useCreateIpamReservation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      subnet,
      payload,
    }: {
      subnet: string;
      payload: { start_ip: string; end_ip?: string | null; reason?: string };
    }) =>
      apiRequest(
        `/ipam/subnets/${encodeURIComponent(subnet)}/reservations`,
        { method: 'POST', body: payload },
      ),
    onSuccess: () => invalidateOverview(qc),
  });
}

export function useDeleteIpamReservation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/ipam/reservations/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateOverview(qc),
  });
}

export function useCreateIpamAllocation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      subnet,
      payload,
    }: {
      subnet: string;
      payload: { address: string; hostname?: string; description?: string };
    }) =>
      apiRequest(
        `/ipam/subnets/${encodeURIComponent(subnet)}/allocations`,
        { method: 'POST', body: payload },
      ),
    onSuccess: () => invalidateOverview(qc),
  });
}

export function useDeleteIpamAllocation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/ipam/allocations/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateOverview(qc),
  });
}

// ── DHCP mutations ─────────────────────────────────────────────────────────

export interface DhcpServerPayload {
  provider: string;
  name: string;
  base_url: string;
  auth_type: string;
  auth_config?: Record<string, string>;
  notes?: string;
  enabled: boolean;
  verify_tls: boolean;
}

export function useCreateDhcpServer() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: DhcpServerPayload) =>
      apiRequest('/dhcp/servers', { method: 'POST', body: payload }),
    onSuccess: () => invalidateDhcp(qc),
  });
}

export function useUpdateDhcpServer() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, payload }: { id: number; payload: DhcpServerPayload }) =>
      apiRequest(`/dhcp/servers/${id}`, { method: 'PATCH', body: payload }),
    onSuccess: () => invalidateDhcp(qc),
  });
}

export function useDeleteDhcpServer() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/dhcp/servers/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateDhcp(qc),
  });
}

export function useSyncDhcpServer() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/dhcp/servers/${id}/sync`, { method: 'POST' }),
    onSuccess: () => invalidateDhcp(qc),
  });
}
