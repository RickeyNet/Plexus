/**
 * Topology API hooks - graph data, positions, discovery, STP, changes, util.
 *
 * Mirrors the legacy api.js topology helpers on top of apiRequest.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest, getCsrfToken } from './client';

// ── Types ──────────────────────────────────────────────────────────────────

export interface TopologyEdgeUtilization {
  utilization_pct: number;
  in_bps?: number;
  out_bps?: number;
  width?: number;
  color?: { color: string; highlight: string; hover: string; opacity: number };
}

export interface TopologyNode {
  id: number | string;
  label: string;
  ip?: string | null;
  device_type?: string | null;
  device_category?: string | null;
  model?: string | null;
  platform?: string | null;
  status?: string | null;
  group_name?: string | null;
  in_inventory: boolean;
  ipam_subnet?: string | null;
  ipam_utilization_pct?: number | null;
}

export interface TopologyEdge {
  id: number | string;
  from: number | string;
  to: number | string;
  from_host_id?: number | null;
  to_host_id?: number | null;
  source_interface?: string | null;
  target_interface?: string | null;
  protocol?: string | null;
  utilization?: TopologyEdgeUtilization | null;
}

export interface TopologyData {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  unacknowledged_changes?: number;
}

export type TopologyPositions = Record<string, { x: number; y: number }>;

export interface TopologyChange {
  source_host_id?: number | null;
  source_hostname?: string | null;
  source_interface?: string | null;
  target_device_name?: string | null;
  target_ip?: string | null;
  target_interface?: string | null;
  protocol?: string | null;
  change_type: 'added' | 'removed' | string;
  detected_at: string;
  acknowledged?: boolean;
}

export interface StpState {
  host_id: number;
  hostname?: string | null;
  interface_name?: string | null;
  vlan_id?: number | string | null;
  port_state?: string | null;
  port_role?: string | null;
}

export interface StpEvent {
  host_id: number;
  hostname?: string | null;
  interface_name?: string | null;
  vlan_id?: number | string | null;
  event_type?: string | null;
  severity?: string | null;
  details?: string | null;
  old_value?: string | null;
  new_value?: string | null;
  created_at?: string | null;
}

export interface StpStateResp {
  states: StpState[];
  count?: number;
  unacknowledged_events?: number;
}

export interface StpScanResult {
  ports_collected: number;
  hosts_scanned: number;
  hosts_updated: number;
  errors: number;
  vlans_scanned?: number[];
  all_vlans?: boolean;
  unacknowledged_events?: number;
}

export interface DiscoveryStreamEvent {
  type: string;
  total_hosts?: number;
  total_groups?: number;
  group?: string;
  host_count?: number;
  hostname?: string;
  ip?: string;
  scanned?: number;
  neighbors?: number;
  ok?: boolean;
  links?: number;
  links_discovered?: number;
  hosts_scanned?: number;
  errors?: number;
  message?: string;
}

export interface InventoryGroupLite {
  id: number;
  name: string;
  description?: string | null;
}

// ── Queries ────────────────────────────────────────────────────────────────

export function useTopology(groupId?: number | string | null) {
  const params = groupId ? `?group_id=${groupId}` : '';
  return useQuery<TopologyData>({
    queryKey: ['topology', groupId ?? null],
    queryFn: () => apiRequest(`/topology${params}`),
  });
}

export function useTopologyPositions() {
  return useQuery<TopologyPositions>({
    queryKey: ['topology-positions'],
    queryFn: () => apiRequest('/topology/positions'),
  });
}

export function useTopologyChanges(unacknowledged = true, limit = 200) {
  return useQuery<{ changes: TopologyChange[] }>({
    queryKey: ['topology-changes', unacknowledged, limit],
    queryFn: () =>
      apiRequest(
        `/topology/changes?unacknowledged=${unacknowledged}&limit=${limit}`,
      ),
    enabled: false,
  });
}

export function useTopologyStpEvents(unacknowledged = true, limit = 200) {
  return useQuery<{ events: StpEvent[]; unacknowledged_count?: number }>({
    queryKey: ['topology-stp-events', unacknowledged, limit],
    queryFn: () =>
      apiRequest(
        `/topology/stp/events?unacknowledged=${unacknowledged}&limit=${limit}`,
      ),
    enabled: false,
  });
}

// ── Mutations ──────────────────────────────────────────────────────────────

export function useSaveTopologyPositions() {
  // Intentionally does NOT invalidate ['topology-positions'] on success. The
  // Topology component applies each drag/pin to its local savedPositionsRef
  // immediately, so this mutation is pure persistence. Invalidating would
  // refetch an identical positions object, and because the topology rebuild
  // effect depends on `positions`, that refetch would destroy and recreate the
  // entire vis-network graph (re-running physics stabilization) on every node
  // drag. The fresh server copy is picked up on the next mount instead.
  return useMutation({
    mutationFn: (positions: Record<string, { x: number; y: number } | null>) =>
      apiRequest('/topology/positions', {
        method: 'PUT',
        body: { positions },
      }),
  });
}

export function useDeleteTopologyPositions() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiRequest('/topology/positions', { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['topology-positions'] }),
  });
}

export function useUpdateHostCategory() {
  return useMutation({
    mutationFn: ({ hostId, category }: { hostId: number; category: string }) =>
      apiRequest(`/hosts/${hostId}/category`, {
        method: 'PATCH',
        body: { device_category: category },
      }),
  });
}

export function useAddHost() {
  const qc = useQueryClient();
  return useMutation<
    { id: number; hostname: string; ip_address: string },
    Error,
    { groupId: number; hostname: string; ipAddress: string; deviceType?: string }
  >({
    mutationFn: ({ groupId, hostname, ipAddress, deviceType = 'unknown' }) =>
      apiRequest(`/inventory/${groupId}/hosts`, {
        method: 'POST',
        body: { hostname, ip_address: ipAddress, device_type: deviceType },
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['topology'] });
      qc.invalidateQueries({ queryKey: ['inventory'] });
    },
  });
}

export function useCreateInventoryGroup() {
  const qc = useQueryClient();
  return useMutation<InventoryGroupLite, Error, { name: string; description?: string }>({
    mutationFn: ({ name, description = '' }) =>
      apiRequest('/inventory', {
        method: 'POST',
        body: { name, description },
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['inventory-groups'] }),
  });
}

export function useAcknowledgeTopologyChanges() {
  return useMutation<{ acknowledged: number }>({
    mutationFn: () =>
      apiRequest('/topology/changes/acknowledge', { method: 'POST' }),
  });
}

export function useAcknowledgeStpEvents() {
  return useMutation<{ acknowledged: number }>({
    mutationFn: () =>
      apiRequest('/topology/stp/events/acknowledge', { method: 'POST' }),
  });
}

export function useDiscoverTopologyStp() {
  return useMutation<
    StpScanResult,
    Error,
    { groupId?: number | string | null; vlanId?: number; allVlans?: boolean; maxVlans?: number }
  >({
    mutationFn: ({ groupId, vlanId = 1, allVlans = false, maxVlans = 128 }) => {
      const params = new URLSearchParams();
      if (groupId) params.set('group_id', String(groupId));
      if (vlanId) params.set('vlan_id', String(vlanId));
      if (allVlans) params.set('all_vlans', 'true');
      if (maxVlans) params.set('max_vlans', String(maxVlans));
      const suffix = params.toString() ? `?${params}` : '';
      return apiRequest(`/topology/stp/discover${suffix}`, { method: 'POST' });
    },
  });
}

export function fetchTopologyStpState(
  groupId?: number | string | null,
  hostId?: number | null,
  vlanId = 1,
  limit = 20000,
): Promise<StpStateResp> {
  const params = new URLSearchParams();
  if (groupId) params.set('group_id', String(groupId));
  if (hostId) params.set('host_id', String(hostId));
  if (vlanId) params.set('vlan_id', String(vlanId));
  params.set('limit', String(limit));
  return apiRequest<StpStateResp>(`/topology/stp?${params}`);
}

export function fetchTopologyChanges(
  unacknowledged = true,
  limit = 200,
): Promise<{ changes: TopologyChange[] }> {
  return apiRequest(
    `/topology/changes?unacknowledged=${unacknowledged}&limit=${limit}`,
  );
}

export function fetchTopologyStpEvents(
  unacknowledged = true,
  limit = 200,
): Promise<{ events: StpEvent[]; unacknowledged_count?: number }> {
  return apiRequest(
    `/topology/stp/events?unacknowledged=${unacknowledged}&limit=${limit}`,
  );
}

// ── SSE Streaming (discovery + utilization) ───────────────────────────────

/**
 * Stream discovery events. Returns an AbortController so caller can cancel.
 * The callback is invoked with each parsed event payload.
 */
export async function discoverTopologyStream(
  groupId: number | string | null | undefined,
  onEvent: (event: DiscoveryStreamEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  const url = groupId
    ? `/api/topology/discover/${groupId}/stream`
    : '/api/topology/discover/stream';
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const csrf = getCsrfToken();
  if (csrf) headers['X-CSRF-Token'] = csrf;

  const res = await fetch(url, {
    method: 'POST',
    headers,
    credentials: 'include',
    signal,
  });
  if (!res.ok || !res.body) {
    throw new Error(`Discovery stream failed: ${res.status} ${res.statusText}`);
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    const parts = buf.split('\n\n');
    buf = parts.pop() ?? '';
    for (const block of parts) {
      // SSE: optionally has `event:` line, but we just look at `data:` lines.
      const lines = block.split('\n');
      const dataLines = lines
        .filter((l) => l.startsWith('data:'))
        .map((l) => l.slice(5).trim());
      if (!dataLines.length) continue;
      const raw = dataLines.join('\n');
      try {
        const ev = JSON.parse(raw) as DiscoveryStreamEvent;
        onEvent(ev);
      } catch {
        /* skip parse errors */
      }
    }
  }
}

export interface UtilizationStreamEdge {
  source_host_id: number | string;
  target_host_id: number | string;
  source_interface: string;
  utilization: TopologyEdgeUtilization;
}

/**
 * Open an EventSource for live utilization. Returns a teardown function.
 */
export function openUtilizationStream(
  intervalSec: number,
  onEdges: (edges: UtilizationStreamEdge[]) => void,
): () => void {
  let es: EventSource | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let stopped = false;

  function open() {
    if (stopped) return;
    try {
      es = new EventSource(
        `/api/topology/utilization/stream?interval=${intervalSec}`,
      );
      es.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.edges) onEdges(data.edges as UtilizationStreamEdge[]);
        } catch {
          /* skip */
        }
      };
      es.onerror = () => {
        if (es) {
          es.close();
          es = null;
        }
        if (!stopped) {
          reconnectTimer = setTimeout(open, 10000);
        }
      };
    } catch {
      /* SSE unsupported */
    }
  }
  open();
  return () => {
    stopped = true;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    if (es) es.close();
  };
}

export function useInventoryGroupsLite() {
  return useQuery<InventoryGroupLite[]>({
    queryKey: ['inventory-groups'],
    queryFn: () => apiRequest('/inventory'),
  });
}

// ── Topology Status Overlay (Phase D) ──────────────────────────────────────

export type AuditSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ErrorSeverity = 'critical' | 'high' | 'warning' | 'info';

export interface TopologyHostStatus {
  host_id: number;
  drift_open: number;
  audit_worst: AuditSeverity | null;
  audit_counts: Partial<Record<AuditSeverity, number>>;
  errors_open: number;
  errors_worst: ErrorSeverity | null;
}

export interface TopologyOverlayStatus {
  latest_audit_run_id: number | null;
  hosts: TopologyHostStatus[];
}

export function useTopologyOverlayStatus(enabled = true) {
  return useQuery<TopologyOverlayStatus>({
    queryKey: ['topology', 'overlay', 'status'],
    queryFn: () => apiRequest('/topology/overlay/status'),
    enabled,
    refetchInterval: enabled ? 60_000 : false,
  });
}
