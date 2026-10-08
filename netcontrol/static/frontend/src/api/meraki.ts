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
export type CloudProvider = 'meraki' | 'cato' | 'fmc';

/** Clouds whose accounts are Cloud Visibility accounts that also feed the map. */
export type CloudAccountProvider = 'aws' | 'azure';

export function isCloudAccountProvider(type: string | null | undefined): type is CloudAccountProvider {
  return type === 'aws' || type === 'azure';
}

export interface CatoBuildOptions {
  site_name_contains: string;
  include_users: boolean;
  include_ranges: boolean;
  inventory_enrich: boolean;
}

/**
 * A Cisco FMC (Secure Firewall Management Center) and the FTDs it manages.
 * Every boolean is one kind of data the collector reads; see the toggles in
 * `FMC_OPTION_TOGGLES`.
 */
export interface FmcBuildOptions {
  /** The FMC API user; the password is the entry's write-only secret. */
  username: string;
  device_name_contains: string;
  /** Every managed device; off draws only the remote access VPN headends. */
  include_all_devices: boolean;
  include_interfaces: boolean;
  /** Virtual routers, static routes, BGP, OSPF, EIGRP, policy-based routes, ECMP zones. */
  include_routing: boolean;
  include_s2s_vpn: boolean;
  include_nat: boolean;
  /** Access control policies, their rules (capped) and prefilter policies. */
  include_access_policies: boolean;
  /** Health alerts and devices with a pending deployment. */
  include_health: boolean;
  include_sessions: boolean;
  verify_tls: boolean;
  inventory_enrich: boolean;
}

export type OrgBuildOptions = MerakiBuildOptions | CatoBuildOptions | FmcBuildOptions;

/** A Meraki organization, a Cato account (`provider` 'cato') or a Cisco FMC (`provider` 'fmc'). */
export interface MerakiOrg {
  id: number;
  name: string;
  provider: CloudProvider;
  /** Meraki organization ID, Cato account ID or FMC domain. */
  org_id: string;
  base_url: string;
  /** The API key / password is write-only: the API only reports whether one is stored. */
  has_api_key: boolean;
  options: OrgBuildOptions;
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
  options: OrgBuildOptions;
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
  /** Integration the node's snapshot came from ('aws' / 'azure' for Cloud Visibility's discovery). */
  provider?: CloudProvider | CloudAccountProvider;
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
  /** Integration whose snapshot holds the subnet. */
  provider?: CloudProvider | CloudAccountProvider;
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

export type ReachabilityStatus = 'ok' | 'blocked' | 'partial' | 'unknown' | 'info';

/** What Path Mode traces: two subnets or addresses and the traffic between them. */
export interface PathTraceQuery {
  source: string;
  destination: string;
  /** Graph node ids of the devices that own the ends, when the page knows them. */
  source_node?: number | string;
  destination_node?: number | string;
  /** tcp / udp / icmp; empty asks about any traffic. */
  protocol: string;
  port?: number;
}

export type PathVerdict = 'allowed' | 'blocked' | 'partial' | 'unknown';

/** What a step of a hop looked at. */
export type PathItemStage = 'policy' | 'acl' | 'security_group' | 'nat' | 'route' | 'link' | 'note';

/** One policy, ACL, security group, NAT rule, route lookup or link a flow hits at a hop. */
export interface PathItem {
  stage: PathItemStage;
  status: ReachabilityStatus;
  /** The rule set, table, NAT rule or route source. */
  where: string;
  text: string;
  /** Index of the matching rule, when one did. */
  rule?: number | null;
}

/** One device (or the Internet) the flow passes, with what it applies, in order. */
export interface PathHop {
  /** Graph node id; null for the Internet pseudo hop. */
  node: number | string | null;
  /** Graph edge taken into this hop; null for the first. */
  edge: number | string | null;
  label: string;
  site: string;
  /** meraki | fmc | cato | aws | azure | inventory | internet | unknown */
  provider: string;
  /** Ingress interface or subnet, "" when none. */
  in: string;
  /** Egress, "" when delivered here. */
  out: string;
  /** Worst of the items: blocked > unknown > partial > ok; info is ignored. */
  status: ReachabilityStatus;
  items: PathItem[];
}

/** The request or the replies of a traced flow. */
export interface PathDirection {
  verdict: PathVerdict;
  summary: string;
  hops: PathHop[];
}

export interface PathAsymmetry {
  status: 'no' | 'yes' | 'unknown';
  text: string;
}

export interface PathEnd {
  address: string;
  node: number | string | null;
  label: string;
  site: string;
}

/** A flow traced hop by hop across every device on the map (`GET /api/topology/path`). */
export interface PathTrace {
  /** False when neither end could be placed; `summary` says why. */
  applies: boolean;
  /** "tcp/443", or "any traffic" when nothing was asked. */
  traffic: string;
  source?: PathEnd;
  destination?: PathEnd;
  verdict: PathVerdict;
  summary: string;
  asymmetric?: PathAsymmetry;
  request?: PathDirection;
  reply?: PathDirection;
  notes?: string[];
}

/** The query string of `GET /api/topology/path`. */
export function pathTraceSearch(query: PathTraceQuery): string {
  const values: Record<string, string | number | undefined> = {
    source: query.source,
    destination: query.destination,
    source_node: query.source_node,
    destination_node: query.destination_node,
    protocol: query.protocol,
    port: query.port,
  };
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== '') params.set(key, String(value));
  }
  return params.toString();
}

export function usePathTrace(query: PathTraceQuery | null) {
  const search = query ? pathTraceSearch(query) : '';
  return useQuery({
    queryKey: ['topology', 'path', search],
    queryFn: () => apiRequest<PathTrace>(`/topology/path?${search}`),
    enabled: query != null,
    staleTime: 60_000,
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
        fmc_default_options: FmcBuildOptions;
      }>('/meraki/orgs'),
    // Keeps the "Building" badge honest for builds this tab isn't tracking
    // (started in another tab, or before a page reload).
    refetchInterval: (query) => (query.state.data?.orgs.some((o) => o.building) ? 4000 : false),
  });
}

/** 'neighbors' is CDP / LLDP discovery of the inventory; the rest are integrations. */
export type TopologySourceType = 'neighbors' | CloudProvider | CloudAccountProvider;

/** One thing that feeds the topology map, with its last collection. */
export interface TopologySource {
  key: string;
  type: TopologySourceType;
  /** Organization id (Meraki, Cato) or Cloud Visibility account id (AWS, Azure). */
  id: number | null;
  name: string;
  status: 'never' | 'success' | 'partial' | 'failed' | string;
  last_collected_at: string | null;
  message: string;
  /** What the last collection found, e.g. "12 sites, 80 devices". */
  detail: string;
  warning_count: number;
  /** The snapshot on the map (Meraki, Cato, Cisco FMC), whose warnings can be listed. */
  snapshot_id?: number | null;
  collecting: boolean;
  can_collect: boolean;
  /** False for an AWS or Azure account switched off in Cloud Visibility. */
  enabled: boolean;
  demo: boolean;
}

export function useTopologySources(enabled = true) {
  return useQuery({
    queryKey: ['meraki', 'sources'],
    queryFn: () => apiRequest<{ sources: TopologySource[] }>('/topology/sources'),
    enabled,
    // Collections are background jobs with no push channel.
    refetchInterval: (query) => (query.state.data?.sources.some((s) => s.collecting) ? 4000 : false),
  });
}

export function useMerakiSnapshots() {
  return useQuery({
    queryKey: ['meraki', 'snapshots'],
    queryFn: () => apiRequest<{ snapshots: MerakiSnapshot[] }>('/meraki/snapshots'),
  });
}

/** An API call a collection could not make (refused, not licensed, timed out...). */
export interface CollectionWarning {
  scope: string;
  /** The API path or query that failed. */
  path: string;
  status: number | null;
  message: string;
}

export function useSnapshotWarnings(snapshotId: number | null) {
  return useQuery({
    queryKey: ['meraki', 'snapshot-warnings', snapshotId],
    queryFn: () =>
      apiRequest<{ snapshot_id: number; warnings: CollectionWarning[] }>(`/meraki/snapshots/${snapshotId}/warnings`),
    enabled: snapshotId != null,
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
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['meraki', 'orgs'] });
      qc.invalidateQueries({ queryKey: ['meraki', 'sources'] });
    },
  });
}

export function useBuildMerakiSample() {
  const qc = useQueryClient();
  return useMutation({
    // 'aws' / 'azure' load a demo account, which lives under Cloud Visibility.
    mutationFn: (provider: CloudProvider | CloudAccountProvider) =>
      apiRequest<MerakiBuildResult & { org_ref: number }>(
        `/meraki/sample${provider === 'meraki' ? '' : `?provider=${provider}`}`,
        { method: 'POST' },
      ),
    onSuccess: () => {
      invalidateMeraki(qc);
      qc.invalidateQueries({ queryKey: ['cloud-accounts'] });
      qc.invalidateQueries({ queryKey: ['cloud-topology'] });
    },
  });
}

export function useDeleteMerakiSnapshot() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => apiRequest<void>(`/meraki/snapshots/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateMeraki(qc),
  });
}
