import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

export interface MerakiBuildOptions {
  network_tags: string[];
  network_name_contains: string;
  include_lldp_cdp: boolean;
  include_switch_ports: boolean;
  include_port_statuses: boolean;
  include_switch_routing: boolean;
  include_firewall: boolean;
  include_wireless: boolean;
  include_clients: boolean;
  inventory_enrich: boolean;
  ssh_enrich: boolean;
  max_concurrency: number;
  requests_per_second: number;
}

/** Integrations that feed the map through the same organization pipeline. */
export type CloudProvider = 'meraki' | 'cato';

export interface CatoBuildOptions {
  site_name_contains: string;
  include_users: boolean;
  include_ranges: boolean;
  inventory_enrich: boolean;
}

/** A Meraki organization, or a Cato account (`provider` 'cato'). */
export interface MerakiOrg {
  id: number;
  name: string;
  provider: CloudProvider;
  /** Meraki organization ID or Cato account ID. */
  org_id: string;
  base_url: string;
  /** The API key is write-only: the API only reports whether one is stored. */
  has_api_key: boolean;
  options: MerakiBuildOptions | CatoBuildOptions;
  building: boolean;
  snapshot_count?: number;
  last_build_at?: string | null;
  last_build_status?: 'never' | 'success' | 'partial' | 'failed' | string;
  last_build_message?: string | null;
}

export interface MerakiOrgInput {
  name: string;
  /** Set on create only; an entry never changes provider. */
  provider?: CloudProvider;
  org_id: string;
  base_url: string;
  api_key?: string;
  options: MerakiBuildOptions | CatoBuildOptions;
}

export interface MerakiSnapshotSummary {
  sites?: number;
  devices?: number;
  devices_by_kind?: Record<string, number>;
  devices_by_status?: Record<string, number>;
  external_neighbors?: number;
  inventory_matches?: number;
  lan_links?: number;
  vpn_tunnels?: number;
  wan_uplinks?: number;
  vlans?: number;
  /** Cato only: remote users connected when the collection ran. */
  remote_users?: number;
}

export interface MerakiSnapshot {
  id: number;
  org_ref: number;
  org_name?: string;
  summary: MerakiSnapshotSummary;
  warning_count: number;
  duration_seconds: number;
  built_by?: string;
  created_at: string;
}

export interface MerakiBuildResult {
  snapshot_id: number;
  summary: MerakiSnapshotSummary;
  warning_count: number;
  duration_seconds: number;
}

export interface MerakiBuildJob {
  job_id: string;
  status: 'running' | 'completed' | 'partial' | 'failed';
  progress: {
    phase?: string;
    calls_done?: number;
    calls_total?: number;
    networks?: number;
    devices?: number;
    hosts_done?: number;
    hosts_total?: number;
  };
  result: MerakiBuildResult | null;
  error: string | null;
}

export interface MerakiValidateResult {
  ok: boolean;
  message: string;
  organizations: { id: string; name: string }[];
}

export interface DetailSection {
  title: string;
  kind: 'kv' | 'table' | 'text';
  columns?: string[];
  rows?: string[][];
  text?: string;
}

export interface MerakiNodeDetails {
  /** Integration the node's snapshot came from. */
  provider?: CloudProvider;
  node_id: string;
  label: string;
  kind: string;
  model: string;
  status: string;
  generated_at: string;
  site_name: string;
  sections: DetailSection[];
  /** Site-wide configuration, present when the node is the site's appliance. */
  site_sections: DetailSection[];
  /** The site's VLAN / LAN addressing, for every managed device of the site. */
  site_addressing: DetailSection[];
}

/** A subnet and the device that owns it, for picking path endpoints. */
export interface MerakiSubnet {
  org_ref: number;
  cidr: string;
  name: string;
  /** vlan / lan / static (behind the appliance), svi (L3 switch), peer (non-Meraki VPN peer), range (Cato site). */
  kind: string;
  site_id: string;
  site_name: string;
  node_id: string;
  /** Whether the site advertises the subnet into the VPN; null when unknown. */
  in_vpn: boolean | null;
}

export interface TopologyDeepSearchHit {
  org_ref: number;
  node_id: string;
  label: string;
  snippet: string;
}

export function topologyExportUrl(groupId: number | null, download = false): string {
  const params = new URLSearchParams();
  if (groupId != null) params.set('group_id', String(groupId));
  if (download) params.set('download', '1');
  const query = params.toString();
  return `/api/topology/export.html${query ? `?${query}` : ''}`;
}

export function useMerakiNodeDetails(orgRef: number | null, nodeId: string | null) {
  return useQuery({
    queryKey: ['meraki', 'node', orgRef, nodeId],
    queryFn: () =>
      apiRequest<MerakiNodeDetails>(
        `/meraki/nodes?org_ref=${orgRef}&node_id=${encodeURIComponent(nodeId ?? '')}`,
      ),
    enabled: orgRef != null && nodeId != null,
  });
}

export function useMerakiSubnets(enabled: boolean) {
  return useQuery({
    queryKey: ['meraki', 'subnets'],
    queryFn: () => apiRequest<{ subnets: MerakiSubnet[] }>('/meraki/subnets'),
    enabled,
  });
}

export function useTopologyDeepSearch(query: string) {
  const q = query.trim();
  return useQuery({
    queryKey: ['topology', 'deep-search', q],
    queryFn: () =>
      apiRequest<{ results: TopologyDeepSearchHit[]; truncated: boolean }>(
        `/topology/search/deep?q=${encodeURIComponent(q)}`,
      ),
    enabled: q.length >= 2,
  });
}

export function useMerakiOrgs() {
  return useQuery({
    queryKey: ['meraki', 'orgs'],
    queryFn: () =>
      apiRequest<{
        orgs: MerakiOrg[];
        default_options: MerakiBuildOptions;
        cato_default_options: CatoBuildOptions;
      }>('/meraki/orgs'),
    // Keeps the "Building" badge honest for builds this tab isn't tracking
    // (started in another tab, or before a page reload).
    refetchInterval: (query) => (query.state.data?.orgs.some((o) => o.building) ? 4000 : false),
  });
}

export function useMerakiSnapshots() {
  return useQuery({
    queryKey: ['meraki', 'snapshots'],
    queryFn: () => apiRequest<{ snapshots: MerakiSnapshot[] }>('/meraki/snapshots'),
  });
}

export function useMerakiBuildJob(jobId: string | null) {
  return useQuery({
    queryKey: ['meraki', 'build', jobId],
    queryFn: () => apiRequest<MerakiBuildJob>(`/meraki/builds/${jobId}`),
    enabled: jobId != null,
    // A build is a background job with no push channel; poll until it settles
    // (or the job record is gone, which surfaces as an error).
    refetchInterval: (query) => {
      if (query.state.status === 'error') return false;
      return !query.state.data || query.state.data.status === 'running' ? 1500 : false;
    },
    retry: false,
  });
}

// Meraki data is merged into the topology graph server-side, so anything
// that changes it also invalidates the graph (and its deep-search results).
function invalidateMeraki(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: ['meraki'] });
  qc.invalidateQueries({ queryKey: ['topology'] });
  // Meraki clients are part of the MAC tracking search.
  qc.invalidateQueries({ queryKey: ['mac-tracking'] });
}

export function useCreateMerakiOrg() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: MerakiOrgInput) =>
      apiRequest<{ org: MerakiOrg }>('/meraki/orgs', { method: 'POST', body }),
    onSuccess: () => invalidateMeraki(qc),
  });
}

export function useUpdateMerakiOrg() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: number; body: Partial<MerakiOrgInput> }) =>
      apiRequest<{ org: MerakiOrg }>(`/meraki/orgs/${id}`, { method: 'PUT', body }),
    onSuccess: () => invalidateMeraki(qc),
  });
}

export function useDeleteMerakiOrg() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => apiRequest<void>(`/meraki/orgs/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateMeraki(qc),
  });
}

export function useValidateMerakiOrg() {
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest<MerakiValidateResult>(`/meraki/orgs/${id}/validate`, { method: 'POST' }),
  });
}

export function useStartMerakiBuild() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest<{ job_id: string }>(`/meraki/orgs/${id}/build`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['meraki', 'orgs'] }),
  });
}

export function useBuildMerakiSample() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (provider: CloudProvider) =>
      apiRequest<MerakiBuildResult & { org_ref: number }>(
        `/meraki/sample${provider === 'cato' ? '?provider=cato' : ''}`,
        { method: 'POST' },
      ),
    onSuccess: () => invalidateMeraki(qc),
  });
}

export function useDeleteMerakiSnapshot() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => apiRequest<void>(`/meraki/snapshots/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateMeraki(qc),
  });
}
