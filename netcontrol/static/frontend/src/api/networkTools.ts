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
}

export function useMacSearch(query: string) {
  return useQuery({
    queryKey: ['mac-tracking', 'search', query],
    queryFn: () =>
      apiRequest<MacEntry[]>(
        `/mac-tracking/search?query=${encodeURIComponent(query)}`,
      ),
    enabled: query.trim().length > 0,
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

export function useTriggerMacCollection() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (hostId?: number) => {
      const path = hostId
        ? `/mac-tracking/collect?host_id=${hostId}`
        : '/mac-tracking/collect';
      return apiRequest<MacCollectResult>(path, { method: 'POST' });
    },
    onSuccess: () => {
      // Newly-collected entries should appear on the next search.
      qc.invalidateQueries({ queryKey: ['mac-tracking'] });
    },
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
