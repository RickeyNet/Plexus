/**
 * Monitoring, SLA, availability, and capacity-planning API hooks.
 * Backend endpoints under /api/monitoring, /api/sla, /api/availability,
 * /api/metrics/capacity-planning.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest, getCsrfToken } from './client';

// ── Types ─────────────────────────────────────────────────────────────────

export interface MonitoringSummary {
  monitored_hosts?: number;
  avg_cpu?: number | null;
  avg_memory?: number | null;
  interfaces_up?: number;
  interfaces_down?: number;
  vpn_tunnels_up?: number;
  vpn_tunnels_down?: number;
  total_routes?: number;
  open_alerts?: number;
}

export interface MonitoringPoll {
  host_id: number;
  hostname?: string | null;
  ip_address?: string | null;
  device_type?: string | null;
  cpu_percent?: number | null;
  memory_percent?: number | null;
  memory_used_mb?: number | null;
  memory_total_mb?: number | null;
  if_up_count: number;
  if_down_count: number;
  if_admin_down: number;
  vpn_tunnels_up: number;
  vpn_tunnels_down: number;
  route_count: number;
  uptime_seconds?: number | null;
  poll_status?: string;
  poll_error?: string | null;
  polled_at?: string | null;
  if_details?: string | null;
  vpn_details?: string | null;
}

export type AlertSeverity = 'critical' | 'warning' | 'info';

export interface MonitoringAlert {
  id: number;
  host_id: number;
  hostname?: string | null;
  ip_address?: string | null;
  metric: string;
  severity: AlertSeverity | string;
  message: string;
  acknowledged: boolean;
  acknowledged_by?: string | null;
  created_at?: string | null;
  last_seen_at?: string | null;
  occurrence_count?: number;
  escalated?: boolean;
  original_severity?: string | null;
  rule_id?: number | null;
}

export interface MonitoringRouteSnapshot {
  id: number;
  host_id: number;
  captured_at: string;
  route_count: number;
  routes_text?: string;
}

export interface AlertRule {
  id: number;
  name: string;
  metric: string;
  operator: string;
  value: number;
  severity: string;
  enabled: boolean;
  cooldown_minutes: number;
  escalate_after_minutes: number;
  escalate_to?: string;
  description?: string | null;
  hostname?: string | null;
  group_name?: string | null;
  host_id?: number | null;
  group_id?: number | null;
}

export interface AlertSuppression {
  id: number;
  name: string;
  starts_at: string;
  ends_at: string;
  metric?: string | null;
  reason?: string | null;
  hostname?: string | null;
  group_name?: string | null;
  host_id?: number | null;
  group_id?: number | null;
  created_by?: string | null;
}

export interface SlaHostSummary {
  host_id: number;
  hostname?: string | null;
  ip_address?: string | null;
  uptime_pct?: number | null;
  avg_latency_ms?: number | null;
  jitter_ms?: number | null;
  avg_packet_loss_pct?: number | null;
}

export interface SlaSummary {
  avg_uptime_pct?: number | null;
  avg_latency_ms?: number | null;
  avg_jitter_ms?: number | null;
  avg_packet_loss_pct?: number | null;
  mttr_minutes?: number | null;
  mttd_minutes?: number | null;
  total_alerts?: number;
  resolved_alerts?: number;
  hosts: SlaHostSummary[];
}

export interface SlaDailyPoint {
  day: string;
  uptime_pct?: number | null;
  avg_latency_ms?: number | null;
  jitter_ms?: number | null;
  avg_packet_loss_pct?: number | null;
}

export interface SlaHostDetail {
  hostname?: string;
  ip_address?: string;
  device_type?: string;
  period_days: number;
  total_alerts: number;
  resolved_alerts: number;
  mttr_minutes?: number | null;
  daily?: SlaDailyPoint[];
}

export interface SlaTarget {
  id: number;
  name: string;
  metric: string;
  target_value: number;
  warning_value: number;
  enabled: boolean;
  host_id?: number | null;
  group_id?: number | null;
  host_name?: string | null;
  group_name?: string | null;
}

export interface AvailabilityHost {
  host_id: number;
  hostname?: string | null;
  ip_address?: string | null;
  uptime_pct?: number | null;
  current_state?: string;
}

export interface AvailabilitySummary {
  total_hosts?: number;
  hosts_up?: number;
  hosts_down?: number;
  avg_uptime_pct?: number | null;
  total_outages?: number;
  hosts?: AvailabilityHost[];
}

export interface AvailabilityOutage {
  id: number;
  host_id: number;
  hostname?: string;
  entity_type?: string;
  entity_id?: string;
  started_at?: string | null;
  ended_at?: string | null;
  duration_seconds?: number | null;
}

export interface AvailabilityTransition {
  id: number;
  host_id: number;
  hostname?: string;
  entity_type?: string;
  entity_id?: string;
  old_state?: string;
  new_state?: string;
  changed_at?: string | null;
}

export interface CapacityPlanningPoint {
  timestamp?: string;
  day?: string;
  value: number;
}

export interface CapacityPlanningResponse {
  data_points?: CapacityPlanningPoint[];
  projection?: CapacityPlanningPoint[];
  threshold_estimates?: Record<string, { days_until?: number | null; estimated_date?: string | null }>;
}

export interface PollNowEvent {
  type: 'start' | 'host_done' | 'host_error' | 'done';
  total_hosts?: number;
  completed?: number;
  hostname?: string;
  status?: string;
  cpu?: number | null;
  memory?: number | null;
  alerts?: number;
  hosts_polled?: number;
  alerts_created?: number;
  errors?: number;
}

// ── Queries ──────────────────────────────────────────────────────────────

export function useMonitoringSummary(groupId: number | null = null) {
  const qs = groupId ? `?group_id=${groupId}` : '';
  return useQuery<MonitoringSummary>({
    queryKey: ['monitoring-summary', groupId],
    queryFn: () => apiRequest(`/monitoring/summary${qs}`),
    refetchInterval: 30_000,
  });
}

export function useMonitoringPolls(groupId: number | null = null, limit = 200) {
  const params = new URLSearchParams();
  if (groupId) params.set('group_id', String(groupId));
  if (limit) params.set('limit', String(limit));
  return useQuery<MonitoringPoll[]>({
    queryKey: ['monitoring-polls', groupId, limit],
    queryFn: () => apiRequest(`/monitoring/polls?${params}`),
    refetchInterval: 30_000,
  });
}

export function useMonitoringPollHistory(hostId: number | null, limit = 50) {
  return useQuery<MonitoringPoll[]>({
    queryKey: ['monitoring-poll-history', hostId, limit],
    queryFn: () => apiRequest(`/monitoring/polls/${hostId}/history?limit=${limit}`),
    enabled: hostId != null,
  });
}

export function useMonitoringAlerts(params: { acknowledged?: boolean | null; severity?: string; limit?: number } = {}) {
  const qs = new URLSearchParams();
  if (params.acknowledged === true) qs.set('acknowledged', 'true');
  else if (params.acknowledged === false) qs.set('acknowledged', 'false');
  if (params.severity) qs.set('severity', params.severity);
  qs.set('limit', String(params.limit ?? 200));
  return useQuery<MonitoringAlert[]>({
    queryKey: ['monitoring-alerts', params.acknowledged ?? null, params.severity ?? '', params.limit ?? 200],
    queryFn: () => apiRequest(`/monitoring/alerts?${qs}`),
    refetchInterval: 30_000,
  });
}

export function useMonitoringRouteSnapshots(hostId: number | null, limit = 10) {
  return useQuery<MonitoringRouteSnapshot[]>({
    queryKey: ['monitoring-route-snapshots', hostId, limit],
    queryFn: () => apiRequest(`/monitoring/routes/${hostId}?limit=${limit}`),
    enabled: hostId != null,
  });
}

export function useAlertRules() {
  return useQuery<AlertRule[]>({
    queryKey: ['alert-rules'],
    queryFn: () => apiRequest('/monitoring/rules'),
  });
}

export function useAlertSuppressions() {
  return useQuery<AlertSuppression[]>({
    queryKey: ['alert-suppressions'],
    queryFn: () => apiRequest('/monitoring/suppressions'),
  });
}

export function useSlaSummary(days = 30, groupId: number | null = null) {
  const params = new URLSearchParams();
  params.set('days', String(days));
  if (groupId) params.set('group_id', String(groupId));
  return useQuery<SlaSummary>({
    queryKey: ['sla-summary', days, groupId],
    queryFn: () => apiRequest(`/sla/summary?${params}`),
  });
}

export function useSlaHostDetail(hostId: number | null, days = 30) {
  return useQuery<SlaHostDetail>({
    queryKey: ['sla-host-detail', hostId, days],
    queryFn: () => apiRequest(`/sla/host/${hostId}?days=${days}`),
    enabled: hostId != null,
  });
}

export function useSlaTargets() {
  return useQuery<SlaTarget[]>({
    queryKey: ['sla-targets'],
    queryFn: () => apiRequest('/sla/targets'),
  });
}

export function useAvailabilitySummary(groupId: number | null = null, days = 7) {
  const params = new URLSearchParams();
  params.set('days', String(days));
  if (groupId) params.set('group_id', String(groupId));
  return useQuery<AvailabilitySummary>({
    queryKey: ['availability-summary', groupId, days],
    queryFn: () => apiRequest(`/availability/summary?${params}`),
  });
}

export function useAvailabilityOutages(params: { groupId?: number | null; days?: number; limit?: number } = {}) {
  const qs = new URLSearchParams();
  if (params.groupId) qs.set('group_id', String(params.groupId));
  if (params.days) qs.set('days', String(params.days));
  qs.set('limit', String(params.limit ?? 200));
  return useQuery<{ outages: AvailabilityOutage[] }>({
    queryKey: ['availability-outages', params.groupId ?? null, params.days ?? 7, params.limit ?? 200],
    queryFn: () => apiRequest(`/availability/outages?${qs}`),
  });
}

export function useAvailabilityTransitions(limit = 500) {
  return useQuery<{ transitions: AvailabilityTransition[] }>({
    queryKey: ['availability-transitions', limit],
    queryFn: () => apiRequest(`/availability/transitions?limit=${limit}`),
  });
}

export function useCapacityPlanning(params: {
  metric: string;
  range: string;
  group?: number | null;
  projectionDays?: number;
  threshold?: number;
}) {
  const qs = new URLSearchParams();
  qs.set('metric', params.metric);
  qs.set('range', params.range);
  if (params.group) qs.set('group', String(params.group));
  qs.set('projection_days', String(params.projectionDays ?? 90));
  qs.set('threshold', String(params.threshold ?? 80));
  return useQuery<CapacityPlanningResponse>({
    queryKey: ['capacity-planning', params.metric, params.range, params.group ?? null, params.projectionDays ?? 90, params.threshold ?? 80],
    queryFn: () => apiRequest(`/metrics/capacity-planning?${qs}`),
  });
}

// ── Mutations ────────────────────────────────────────────────────────────

function invalidateAlerts(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: ['monitoring-alerts'] });
  qc.invalidateQueries({ queryKey: ['monitoring-summary'] });
}

export function useAcknowledgeAlert() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (alertId: number) =>
      apiRequest(`/monitoring/alerts/${alertId}/acknowledge`, { method: 'POST' }),
    onSuccess: () => invalidateAlerts(qc),
  });
}

export function useBulkAcknowledgeAlerts() {
  const qc = useQueryClient();
  return useMutation<{ acknowledged: number }, Error, number[]>({
    mutationFn: (alertIds) =>
      apiRequest('/monitoring/alerts/bulk-acknowledge', {
        method: 'POST',
        body: { alert_ids: alertIds },
      }),
    onSuccess: () => invalidateAlerts(qc),
  });
}

export interface AlertRuleCreate {
  name: string;
  metric: string;
  operator: string;
  value: number;
  severity: string;
  cooldown_minutes: number;
  escalate_after_minutes: number;
  escalate_to?: string;
  description?: string;
  host_id?: number;
  group_id?: number;
}

export function useCreateAlertRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: AlertRuleCreate) =>
      apiRequest('/monitoring/rules', { method: 'POST', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alert-rules'] }),
  });
}

export function useUpdateAlertRule() {
  const qc = useQueryClient();
  return useMutation<AlertRule, Error, { id: number; data: Partial<AlertRuleCreate> & { enabled?: boolean } }>({
    mutationFn: ({ id, data }) =>
      apiRequest(`/monitoring/rules/${id}`, { method: 'PUT', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alert-rules'] }),
  });
}

export function useDeleteAlertRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/monitoring/rules/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alert-rules'] }),
  });
}

export interface SuppressionCreate {
  name: string;
  starts_at: string;
  ends_at: string;
  metric?: string;
  reason?: string;
  host_id?: number;
  group_id?: number;
}

export function useCreateSuppression() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: SuppressionCreate) =>
      apiRequest('/monitoring/suppressions', { method: 'POST', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alert-suppressions'] }),
  });
}

export function useDeleteSuppression() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/monitoring/suppressions/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alert-suppressions'] }),
  });
}

export interface SlaTargetCreate {
  name: string;
  metric: string;
  target_value: number;
  warning_value: number;
  host_id?: number | null;
  group_id?: number | null;
}

export function useCreateSlaTarget() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: SlaTargetCreate) =>
      apiRequest('/sla/targets', { method: 'POST', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sla-targets'] }),
  });
}

export function useUpdateSlaTarget() {
  const qc = useQueryClient();
  return useMutation<SlaTarget, Error, { id: number; data: Partial<SlaTargetCreate> & { enabled?: boolean } }>({
    mutationFn: ({ id, data }) =>
      apiRequest(`/sla/targets/${id}`, { method: 'PUT', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sla-targets'] }),
  });
}

export function useDeleteSlaTarget() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/sla/targets/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sla-targets'] }),
  });
}

// ── Streaming poll-now ───────────────────────────────────────────────────

export async function streamPollNow(
  onEvent: (event: PollNowEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'text/event-stream',
  };
  const csrf = getCsrfToken();
  if (csrf) headers['X-CSRF-Token'] = csrf;

  const res = await fetch('/api/monitoring/poll-now/stream', {
    method: 'POST',
    credentials: 'include',
    headers,
    signal,
  });

  if (!res.ok || !res.body) {
    const text = await res.text().catch(() => '');
    throw new Error(text || `Poll stream failed: ${res.status}`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  const flushEvent = (rawEvent: string) => {
    // SSE event blocks may contain id:/event:/retry:/data: lines. Multi-line
    // data: is concatenated with newlines per the spec. We only care about
    // data: payloads here.
    const dataLines: string[] = [];
    for (const line of rawEvent.split('\n')) {
      if (line.startsWith('data:')) {
        dataLines.push(line.slice(5).replace(/^ /, ''));
      }
    }
    if (!dataLines.length) return;
    const payload = dataLines.join('\n').trim();
    if (!payload) return;
    try {
      onEvent(JSON.parse(payload) as PollNowEvent);
    } catch {
      // ignore non-JSON heartbeats
    }
  };

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let idx = buffer.indexOf('\n\n');
      while (idx !== -1) {
        const rawEvent = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 2);
        flushEvent(rawEvent);
        idx = buffer.indexOf('\n\n');
      }
    }
    if (buffer.trim()) flushEvent(buffer);
  } finally {
    try {
      reader.releaseLock();
    } catch {
      /* may already be released */
    }
  }
}
