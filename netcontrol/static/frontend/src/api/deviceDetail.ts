import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

// ── Types ──────────────────────────────────────────────────────────────────

export interface MetricPoint {
  sampled_at?: string;
  period_start?: string;
  timestamp?: string;
  val_avg?: number;
  value?: number;
}

export interface MetricQueryResult {
  data: MetricPoint[];
}

export interface InterfaceTimeSeriesEntry {
  if_index: number;
  if_name?: string;
  if_speed_mbps?: number;
  sampled_at: string;
  in_rate_bps?: number | null;
  out_rate_bps?: number | null;
  utilization_pct?: number | null;
}

export interface InterfaceTimeSeriesResult {
  data?: InterfaceTimeSeriesEntry[];
  interfaces?: InterfaceTimeSeriesEntry[];
}

export interface PollIfDetail {
  if_index: number;
  name?: string;
  status?: string;
  speed_mbps?: number;
  in_octets?: number;
  out_octets?: number;
}

export interface MonitoringPoll {
  hostname?: string;
  ip_address?: string;
  vrf_name?: string;
  device_type?: string;
  cpu_percent?: number | null;
  memory_percent?: number | null;
  uptime_seconds?: number | null;
  if_up_count?: number;
  if_down_count?: number;
  if_admin_down?: number;
  polled_at?: string;
  if_details?: string | PollIfDetail[];
}

export interface PollHistoryResult {
  polls?: MonitoringPoll[];
}

export interface MonitoringAlert {
  id: number;
  created_at: string;
  severity: string;
  metric?: string;
  message?: string;
  acknowledged?: boolean;
}

export interface MonitoringAlertsResult {
  alerts?: MonitoringAlert[];
}

export interface ComplianceResult {
  profile_name?: string;
  status?: string;
  score?: number | null;
  scanned_at?: string;
}

export interface SyslogEvent {
  timestamp?: string;
  severity?: string;
  message?: string;
  event_data?: string;
}

export interface InterfaceErrorMetric {
  max_value?: number | null;
}

export interface InterfaceErrorSummaryEntry {
  if_index: number;
  if_name?: string;
  metrics?: Record<string, InterfaceErrorMetric>;
}

export interface InterfaceErrorSummary {
  interfaces?: InterfaceErrorSummaryEntry[];
}

export interface InterfaceErrorEvent {
  id: number;
  created_at: string;
  if_index: number;
  if_name?: string;
  metric_name?: string;
  current_rate?: number | null;
  spike_factor?: number | null;
  severity?: string;
  root_cause_hint?: string;
  root_cause_category?: string;
  acknowledged?: boolean;
  resolved_at?: string | null;
}

export interface InterfaceErrorDetailSeriesPoint {
  sampled_at: string;
  value: number;
}

export interface InterfaceErrorDetail {
  series?: Record<string, InterfaceErrorDetailSeriesPoint[]>;
}

export interface IpamSubnet {
  subnet: string;
  vrf_name?: string;
  utilization_pct?: number | null;
  used_count?: number | null;
  total_count?: number | null;
}

export interface IpamAddressContext {
  matched_subnet?: IpamSubnet | null;
  is_conflict?: boolean;
  conflict_groups?: string[];
}

export interface AnnotationEvent {
  id: number;
  category?: string;
  occurred_at: string;
  description?: string;
}

export interface AnnotationsResult {
  annotations?: AnnotationEvent[];
}

// ── Hooks ──────────────────────────────────────────────────────────────────

export function useMetricQuery(metric: string, hostId: number | null, range: string) {
  return useQuery<MetricQueryResult>({
    queryKey: ['metrics', metric, hostId, range],
    queryFn: () => {
      const p = new URLSearchParams({
        metric,
        host: String(hostId ?? '*'),
        range,
        step: 'auto',
      });
      return apiRequest(`/metrics/query?${p}`);
    },
    enabled: hostId != null,
  });
}

export function useInterfaceTimeSeries(hostId: number | null, range: string) {
  return useQuery<InterfaceTimeSeriesResult>({
    queryKey: ['interface-timeseries', hostId, range],
    queryFn: () => apiRequest(`/metrics/interfaces/${hostId}?range=${range}`),
    enabled: hostId != null,
  });
}

export function useMonitoringAlerts(hostId: number | null, limit = 50) {
  return useQuery<MonitoringAlertsResult>({
    queryKey: ['monitoring-alerts', hostId, limit],
    queryFn: () => apiRequest(`/monitoring/alerts?host_id=${hostId}&limit=${limit}`),
    enabled: hostId != null,
  });
}

export function useMonitoringPollHistory(hostId: number | null, limit = 1) {
  return useQuery<PollHistoryResult>({
    queryKey: ['monitoring-poll-history', hostId, limit],
    queryFn: () => apiRequest(`/monitoring/polls/${hostId}/history?limit=${limit}`),
    enabled: hostId != null,
  });
}

export function useMonitoringPolls(limit = 100) {
  return useQuery<{ polls?: (MonitoringPoll & { host_id?: number })[] }>({
    queryKey: ['monitoring-polls', limit],
    queryFn: () => apiRequest(`/monitoring/polls?limit=${limit}`),
  });
}

export function useComplianceResults(hostId: number | null, limit = 20) {
  return useQuery<{ results?: ComplianceResult[] }>({
    queryKey: ['compliance-results', hostId, limit],
    queryFn: () => apiRequest(`/compliance/results?host_id=${hostId}&limit=${limit}`),
    enabled: hostId != null,
  });
}

export function useSyslogEvents(hostId: number | null, limit = 100) {
  return useQuery<{ events?: SyslogEvent[] }>({
    queryKey: ['syslog-events', hostId, limit],
    queryFn: () =>
      apiRequest(`/metrics/events?host_id=${hostId}&limit=${limit}&event_type=syslog`),
    enabled: hostId != null,
  });
}

export function useInterfaceErrorSummary(hostId: number | null, days = 1) {
  return useQuery<InterfaceErrorSummary>({
    queryKey: ['interface-error-summary', hostId, days],
    queryFn: () => apiRequest(`/interfaces/${hostId}/errors?days=${days}`),
    enabled: hostId != null,
  });
}

export function useInterfaceErrorEvents(hostId: number | null, limit = 50) {
  return useQuery<InterfaceErrorEvent[]>({
    queryKey: ['interface-error-events', hostId, limit],
    queryFn: () => apiRequest(`/interface-error-events?host_id=${hostId}&limit=${limit}`),
    enabled: hostId != null,
  });
}

export function useInterfaceErrorDetail(
  hostId: number | null,
  ifIndex: number | null,
  enabled: boolean,
) {
  return useQuery<InterfaceErrorDetail>({
    queryKey: ['interface-error-detail', hostId, ifIndex],
    queryFn: () => apiRequest(`/interfaces/${hostId}/port/${ifIndex}/errors`),
    enabled: enabled && hostId != null && ifIndex != null,
  });
}

export function useIpamAddressContext(ip: string | null, vrf: string | null) {
  return useQuery<IpamAddressContext>({
    queryKey: ['ipam-address-context', ip, vrf],
    queryFn: () => {
      const qs = vrf ? `?vrf=${encodeURIComponent(vrf)}` : '';
      return apiRequest(`/ipam/address/${encodeURIComponent(ip ?? '')}${qs}`);
    },
    enabled: !!ip,
  });
}

export function useAcknowledgeErrorEvent() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (eventId: number) =>
      apiRequest(`/interface-error-events/${eventId}/acknowledge`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['interface-error-events'] }),
  });
}

export function useResolveErrorEvent() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (eventId: number) =>
      apiRequest(`/interface-error-events/${eventId}/resolve`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['interface-error-events'] }),
  });
}
