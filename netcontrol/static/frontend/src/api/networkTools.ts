import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

// ── MAC tracking ────────────────────────────────────────────────────────────

export interface MacEntry {
  mac_address: string;
  ip_address: string | null;
  hostname: string | null;
  host_id: number;
  port_name: string | null;
  vlan: number | null;
  entry_type: string | null;
  first_seen: string | null;
  last_seen: string | null;
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
}

export function useMacTrackingStats() {
  return useQuery({
    queryKey: ['mac-tracking', 'stats'],
    queryFn: () => apiRequest<MacTrackingStats>('/mac-tracking/stats'),
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
    queryFn: () => apiRequest<MacHostRollup[]>('/mac-tracking/by-host'),
  });
}

export function useMacSearch(query: string) {
  // A blank query returns the most recently collected entries, so this query
  // is always enabled - that's what lets newly-collected MACs show up without
  // the user having to type a search term.
  return useQuery({
    queryKey: ['mac-tracking', 'search', query],
    queryFn: () =>
      apiRequest<MacEntry[]>(
        `/mac-tracking/search?query=${encodeURIComponent(query)}`,
      ),
  });
}

export function useMacHistory(macAddress: string | null) {
  return useQuery({
    queryKey: ['mac-tracking', 'history', macAddress],
    queryFn: () =>
      apiRequest<MacHistoryEntry[]>(
        `/mac-tracking/history/${encodeURIComponent(macAddress ?? '')}`,
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
    queryFn: () =>
      apiRequest<MacMoveEvent[]>(`/mac-tracking/moves?${params}`),
  });
}

export function useMacMoveSummary() {
  return useQuery({
    queryKey: ['mac-tracking', 'moves-summary'],
    queryFn: () => apiRequest<MacMoveSummary>('/mac-tracking/moves/summary'),
  });
}

export function useMacMoveEventHistory(eventId: number | null, limit = 500) {
  return useQuery({
    queryKey: ['mac-tracking', 'move-history', eventId, limit],
    queryFn: () =>
      apiRequest<MacMoveEventHistoryEntry[]>(
        `/mac-tracking/moves/${eventId}/history?limit=${limit}`,
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
    queryFn: () => apiRequest<MacCollectJob>(`/mac-tracking/collect/jobs/${jobId}`),
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

function withHost(base: string, hostId?: number | null): string {
  return hostId ? `${base}&host_id=${hostId}` : base;
}

export function useFlowStatus() {
  return useQuery({
    queryKey: ['flows', 'status'],
    queryFn: () => apiRequest<FlowStatus>('/flows/status'),
    staleTime: 10_000,
  });
}

export function useFlowTopTalkers(args: {
  hours: number;
  direction: FlowDirection;
  hostId?: number | null;
  limit?: number;
}) {
  const { hours, direction, hostId, limit = 15 } = args;
  return useQuery({
    queryKey: ['flows', 'top-talkers', hours, direction, limit, hostId ?? null],
    queryFn: () =>
      apiRequest<FlowTalker[]>(
        withHost(
          `/flows/top-talkers?hours=${hours}&direction=${direction}&limit=${limit}`,
          hostId,
        ),
      ),
  });
}

export function useFlowTopApplications(args: {
  hours: number;
  hostId?: number | null;
  limit?: number;
}) {
  const { hours, hostId, limit = 15 } = args;
  return useQuery({
    queryKey: ['flows', 'top-applications', hours, limit, hostId ?? null],
    queryFn: () =>
      apiRequest<FlowApplication[]>(
        withHost(`/flows/top-applications?hours=${hours}&limit=${limit}`, hostId),
      ),
  });
}

export function useFlowTopConversations(args: {
  hours: number;
  hostId?: number | null;
  limit?: number;
}) {
  const { hours, hostId, limit = 15 } = args;
  return useQuery({
    queryKey: ['flows', 'top-conversations', hours, limit, hostId ?? null],
    queryFn: () =>
      apiRequest<FlowConversation[]>(
        withHost(`/flows/top-conversations?hours=${hours}&limit=${limit}`, hostId),
      ),
  });
}

export function useFlowTimeline(args: { hours: number; hostId?: number | null }) {
  const { hours, hostId } = args;
  // Match the bucket-size logic in the legacy module so timeline shape stays
  // consistent: tighter bucketing for short windows, coarser for long ones.
  const bucketMinutes = hours <= 1 ? 1 : hours <= 6 ? 5 : 15;
  return useQuery({
    queryKey: ['flows', 'timeline', hours, bucketMinutes, hostId ?? null],
    queryFn: () =>
      apiRequest<FlowTimelinePoint[]>(
        withHost(
          `/flows/timeline?hours=${hours}&bucket_minutes=${bucketMinutes}`,
          hostId,
        ),
      ),
  });
}

export function useFlowExporters() {
  return useQuery({
    queryKey: ['flows', 'exporters'],
    queryFn: () => apiRequest<FlowExportersResponse>('/flows/exporters'),
    staleTime: 15_000,
  });
}
