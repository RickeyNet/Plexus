import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

// ── MAC tracking ────────────────────────────────────────────────────────────

export interface MacEntry {
  mac_address: string;
  ip_address: string | null;
  hostname: string | null;
  /** Inventory host the entry was learned on; null for a Meraki client. */
  host_id: number | null;
  port_name: string | null;
  vlan: number | null;
  entry_type: string | null;
  first_seen: string | null;
  last_seen: string | null;
  /** 'meraki' for a client seen on a Meraki device (hostname is that device). */
  source?: 'meraki';
  org_ref?: number;
  org_name?: string;
  /** The Meraki device's node in its organization's topology snapshot. */
  node_id?: string;
  network_name?: string;
  description?: string;
  manufacturer?: string;
  ssid?: string;
  status?: string;
}

export interface MacHistoryEntry {
  seen_at: string | null;
  hostname: string | null;
  host_id: number;
  port_name: string | null;
  vlan: number | null;
  ip_address: string | null;
}

export interface MacCollectResult {
  macs_found: number;
  arps_found: number;
  hosts_collected: number;
  errors?: string[];
  host_errors?: { host_id: number; hostname: string; errors: string[] }[];
}

export interface MacTrackingStats {
  total_entries: number;
  unique_macs: number;
  switches_reporting: number;
  last_collected_at: string | null;
  meraki_clients: number;
  meraki_devices: number;
}

export function useMacTrackingStats() {
  return useQuery({
    queryKey: ['mac-tracking', 'stats'],
    queryFn: ({ signal }) => apiRequest<MacTrackingStats>('/mac-tracking/stats', { signal }),
  });
}

export interface MacHostRollup {
  host_id: number;
  hostname: string;
  ip_address: string;
  device_type: string;
  group_id: number | null;
  group_name: string | null;
  snmp_enabled: boolean;
  mac_count: number;
  unique_macs: number;
  last_mac_seen: string | null;
  arp_count: number;
  last_arp_seen: string | null;
}

export function useMacTrackingByHost() {
  return useQuery({
    queryKey: ['mac-tracking', 'by-host'],
    queryFn: ({ signal }) => apiRequest<MacHostRollup[]>('/mac-tracking/by-host', { signal }),
  });
}

export function useMacSearch(query: string) {
  // A blank query returns the most recently collected entries, so this query
  // is always enabled - that's what lets newly-collected MACs show up without
  // the user having to type a search term.
  return useQuery({
    queryKey: ['mac-tracking', 'search', query],
    queryFn: ({ signal }) =>
      apiRequest<MacEntry[]>(
        `/mac-tracking/search?query=${encodeURIComponent(query)}`,
        { signal },
      ),
  });
}

export function useMacHistory(macAddress: string | null) {
  return useQuery({
    queryKey: ['mac-tracking', 'history', macAddress],
    queryFn: ({ signal }) =>
      apiRequest<MacHistoryEntry[]>(
        `/mac-tracking/history/${encodeURIComponent(macAddress ?? '')}`,
        { signal },
      ),
    enabled: !!macAddress,
  });
}

// ── MAC move events (drift-style change tracking) ───────────────────────────

export interface MacMoveEvent {
  id: number;
  mac_address: string;
  status: string;
  change_kind: string;
  from_host_id: number | null;
  from_hostname: string | null;
  from_port: string;
  from_vlan: number;
  from_ip: string;
  to_host_id: number | null;
  to_hostname: string | null;
  to_port: string;
  to_vlan: number;
  to_ip: string;
  detected_at: string | null;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
}

export interface MacMoveSummary {
  open: number;
  acknowledged: number;
  total: number;
}

export interface MacMoveEventHistoryEntry {
  id: number;
  event_id: number;
  mac_address: string;
  action: string;
  from_status: string;
  to_status: string;
  actor: string;
  details: string;
  created_at: string | null;
}

export function useMacMoveEvents(
  status: string,
  limit = 200,
  hostId?: number | null,
) {
  const params = new URLSearchParams();
  if (status && status !== 'all') params.set('status', status);
  if (hostId != null) params.set('host_id', String(hostId));
  params.set('limit', String(limit));
  return useQuery({
    queryKey: ['mac-tracking', 'moves', status, limit, hostId ?? null],
    queryFn: ({ signal }) =>
      apiRequest<MacMoveEvent[]>(`/mac-tracking/moves?${params}`, { signal }),
  });
}

export function useMacMoveSummary() {
  return useQuery({
    queryKey: ['mac-tracking', 'moves-summary'],
    queryFn: ({ signal }) => apiRequest<MacMoveSummary>('/mac-tracking/moves/summary', { signal }),
  });
}

export function useMacMoveEventHistory(eventId: number | null, limit = 500) {
  return useQuery({
    queryKey: ['mac-tracking', 'move-history', eventId, limit],
    queryFn: ({ signal }) =>
      apiRequest<MacMoveEventHistoryEntry[]>(
        `/mac-tracking/moves/${eventId}/history?limit=${limit}`,
        { signal },
      ),
    enabled: eventId != null,
  });
}

export function useAcknowledgeMacMove() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (eventId: number) =>
      apiRequest<{ ok: boolean }>(
        `/mac-tracking/moves/${eventId}/acknowledge`,
        { method: 'POST' },
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['mac-tracking', 'moves'] });
      qc.invalidateQueries({ queryKey: ['mac-tracking', 'moves-summary'] });
      qc.invalidateQueries({ queryKey: ['mac-tracking', 'move-history'] });
    },
  });
}

export function useAcknowledgeAllMacMoves() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiRequest<{ ok: boolean; acknowledged: number }>(
        '/mac-tracking/moves/acknowledge-all',
        { method: 'POST', body: { event_ids: [] } },
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['mac-tracking', 'moves'] });
      qc.invalidateQueries({ queryKey: ['mac-tracking', 'moves-summary'] });
      qc.invalidateQueries({ queryKey: ['mac-tracking', 'move-history'] });
    },
  });
}

export function useTriggerMacCollection() {
  const qc = useQueryClient();
  return useMutation({
    // Single-host collection only - it returns the result inline. The
    // all-hosts (fleet) variant runs as a background job; use
    // useStartFleetMacCollection + useMacCollectionJob for that.
    mutationFn: (hostId: number) =>
      apiRequest<MacCollectResult>(
        `/mac-tracking/collect?host_id=${hostId}`,
        { method: 'POST' },
      ),
    onSuccess: () => {
      // Newly-collected entries should appear on the next search.
      qc.invalidateQueries({ queryKey: ['mac-tracking'] });
    },
  });
}

export interface MacCollectJobStart {
  job_id: string;
  status: string;
  hosts_total: number;
}

export interface MacCollectJob {
  job_id: string;
  kind: string;
  status: 'running' | 'completed' | 'partial' | 'failed';
  started_at: string;
  finished_at: string | null;
  progress: {
    hosts_done?: number;
    hosts_total?: number;
    macs_found?: number;
    arps_found?: number;
  };
  result: MacCollectResult | null;
  error: string | null;
}

export function useStartFleetMacCollection() {
  return useMutation({
    mutationFn: () =>
      apiRequest<MacCollectJobStart>('/mac-tracking/collect', {
        method: 'POST',
      }),
  });
}

export function useMacCollectionJob(jobId: string | null) {
  return useQuery({
    // Deliberately NOT under the ['mac-tracking'] prefix: completion
    // invalidates that whole prefix, and the job query itself must not be
    // caught in its own invalidation.
    queryKey: ['mac-collect-job', jobId],
    queryFn: ({ signal }) => apiRequest<MacCollectJob>(`/mac-tracking/collect/jobs/${jobId}`, { signal }),
    enabled: jobId != null,
    refetchInterval: (query) =>
      query.state.data && query.state.data.status !== 'running' ? false : 2000,
  });
}

// ── Traffic analysis (NetFlow / sFlow / IPFIX) ──────────────────────────────

export interface FlowStatus {
  enabled: boolean;
  netflow_port: number;
  sflow_port: number;
  running: boolean;
  sflow_running: boolean;
}

export interface FlowTalker {
  ip: string;
  total_bytes: number;
  flow_count: number;
  asn?: number;
  asn_organization?: string | null;
}

export interface FlowApplication {
  service_name: string | null;
  port: number;
  protocol: number;
  protocol_name: string | null;
  total_bytes: number;
}

export interface FlowConversation {
  src_ip: string;
  dst_ip: string;
  total_bytes: number;
  flow_count: number;
}

/**
 * One interface of an exporter ranked by flow traffic. `if_index` is the
 * number the flow records carry; `if_name` / `if_device` name it when the
 * host's interfaces are known (SNMP polling, an OPNsense collection), else
 * null.
 */
export interface FlowInterface {
  host_id: number | null;
  exporter_ip: string;
  if_index: number;
  if_name: string | null;
  if_device: string | null;
  in_bytes: number;
  out_bytes: number;
  total_bytes: number;
  flow_count: number;
}

export interface FlowTimelinePoint {
  bucket: string | null;
  total_bytes: number;
}

export interface FlowExporter {
  id: number;
  exporter_ip: string;
  host_id: number | null;
  hostname: string | null;
  flow_type: string;
  packets_received: number;
  sampling_rate: number | null;
  first_seen: string | null;
  last_seen: string | null;
  last_record_at: string | null;
}

export interface FlowExportersResponse {
  exporters: FlowExporter[];
  cache_size: number;
}

export type FlowDirection = 'src' | 'dst';

/**
 * Time-range presets the flow endpoints accept: /api/flows/* caps `hours` at
 * 168. Clamp the shared range to these with `clampPreset`.
 */
export const FLOW_RANGES = ['1h', '6h', '24h', '7d'] as const;

function withHost(base: string, hostId?: number | null): string {
  return hostId ? `${base}&host_id=${hostId}` : base;
}

export function useFlowStatus(enabled = true) {
  return useQuery({
    queryKey: ['flows', 'status'],
    queryFn: ({ signal }) => apiRequest<FlowStatus>('/flows/status', { signal }),
    staleTime: 10_000,
    enabled,
  });
}

/** One direction's talkers alone (the Dashboard panel); pages with several flow views use `useFlowViewTalkers`. */
export function useFlowTopTalkers(args: {
  hours: number;
  direction: FlowDirection;
  hostId?: number | null;
  limit?: number;
}) {
  const { hours, direction, hostId, limit = 15 } = args;
  return useQuery({
    queryKey: ['flows', 'top-talkers', hours, direction, limit, hostId ?? null],
    queryFn: ({ signal }) =>
      apiRequest<FlowTalker[]>(
        withHost(
          `/flows/top-talkers?hours=${hours}&direction=${direction}&limit=${limit}`,
          hostId,
        ),
        { signal },
      ),
  });
}

/** Flow views of one window from GET /api/flows/overview (the `parts` asked for). */
export interface FlowOverview {
  top_src?: FlowTalker[];
  top_dst?: FlowTalker[];
  top_applications?: FlowApplication[];
  top_conversations?: FlowConversation[];
  top_interfaces?: FlowInterface[];
  timeline?: FlowTimelinePoint[];
  hours: number;
  bucket_minutes: number;
}

type FlowOverviewPart = Exclude<keyof FlowOverview, 'hours' | 'bucket_minutes'>;

/** Rows per ranked flow view (talkers, applications, conversations, interfaces). */
const FLOW_VIEW_LIMIT = 15;

/** Timeline bucket for a window: tighter for short windows, coarser for long ones. */
export function flowBucketMinutes(hours: number): number {
  return hours <= 1 ? 1 : hours <= 6 ? 5 : 15;
}

interface FlowViewArgs {
  hours: number;
  hostId?: number | null;
}

/**
 * The `parts` of the flow overview one sub-tab of the Traffic Analysis or
 * device Flow page shows, in one request (one scan of the flow records on
 * the server): both talker directions come together, so switching the
 * direction needs no new request, and no tab pays for another tab's views.
 */
function useFlowOverview<T>(
  { hours, hostId }: FlowViewArgs,
  parts: FlowOverviewPart[],
  select: (overview: FlowOverview) => T,
) {
  const bucketMinutes = flowBucketMinutes(hours);
  const partList = parts.join(',');
  return useQuery({
    queryKey: ['flows', 'overview', partList, hours, bucketMinutes, FLOW_VIEW_LIMIT, hostId ?? null],
    queryFn: ({ signal }) =>
      apiRequest<FlowOverview>(
        withHost(
          `/flows/overview?parts=${partList}&hours=${hours}&limit=${FLOW_VIEW_LIMIT}&bucket_minutes=${bucketMinutes}`,
          hostId,
        ),
        { signal },
      ),
    select,
  });
}

const TALKER_PARTS: FlowOverviewPart[] = ['top_src', 'top_dst'];

export function useFlowViewTalkers(args: FlowViewArgs & { direction: FlowDirection }) {
  const { direction } = args;
  return useFlowOverview(args, TALKER_PARTS, (o) =>
    (direction === 'src' ? o.top_src : o.top_dst) ?? [],
  );
}

export function useFlowTopApplications(args: FlowViewArgs) {
  return useFlowOverview(args, ['top_applications'], (o) => o.top_applications ?? []);
}

export function useFlowTopConversations(args: FlowViewArgs) {
  return useFlowOverview(args, ['top_conversations'], (o) => o.top_conversations ?? []);
}

export function useFlowTopInterfaces(args: FlowViewArgs) {
  return useFlowOverview(args, ['top_interfaces'], (o) => o.top_interfaces ?? []);
}

export function useFlowTimeline(args: FlowViewArgs) {
  return useFlowOverview(args, ['timeline'], (o) => o.timeline ?? []);
}

export function useFlowExporters() {
  return useQuery({
    queryKey: ['flows', 'exporters'],
    queryFn: ({ signal }) => apiRequest<FlowExportersResponse>('/flows/exporters', { signal }),
    staleTime: 15_000,
  });
}
