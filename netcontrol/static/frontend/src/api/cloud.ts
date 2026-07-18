/**
 * Cloud Visibility (AWS / Azure / GCP) API hooks.
 * Backend endpoints under /api/cloud.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

// ── Types ─────────────────────────────────────────────────────────────────

export interface CloudProvider {
  id: string;
  live_supported?: boolean;
  missing_dependencies?: string[];
}

export interface CloudAccount {
  id: number;
  provider: string;
  name: string;
  account_identifier?: string | null;
  region_scope?: string | null;
  auth_type?: string | null;
  /** Credentials are write-only: the API never returns auth_config, only this flag. */
  has_auth_config?: boolean;
  /** Server-computed flow/traffic sync readiness (frontend can't see auth_config). */
  sync_readiness?: {
    flow_ready: boolean;
    traffic_ready: boolean;
    flow_missing: string[];
    traffic_missing: string[];
  };
  notes?: string | null;
  enabled?: number | boolean;
  last_sync_status?: string | null;
  last_sync_message?: string | null;
  last_sync_at?: string | null;
  resource_count?: number;
  connection_count?: number;
}

export interface CloudResource {
  resource_uid: string;
  provider?: string;
  resource_type?: string;
  name?: string;
  region?: string;
  cidr?: string;
  status?: string;
  metadata?: Record<string, unknown> | null;
}

export interface CloudConnection {
  provider?: string;
  source_resource_uid?: string;
  source_name?: string;
  target_resource_uid?: string;
  target_name?: string;
  connection_type?: string;
  state?: string;
  metadata?: Record<string, unknown> | null;
}

export interface CloudHybridLink {
  host_hostname?: string;
  host_label?: string;
  cloud_resource_uid?: string;
  cloud_resource_name?: string;
  connection_type?: string;
  state?: string;
  provider?: string;
}

export interface CloudTopologySummary {
  account_count?: number;
  resource_count?: number;
  connection_count?: number;
  hybrid_link_count?: number;
}

export interface CloudTopology {
  resources: CloudResource[];
  connections: CloudConnection[];
  hybrid_links: CloudHybridLink[];
  summary: CloudTopologySummary;
}

export interface CloudFlowSummary {
  flow_count?: number;
  total_bytes?: number;
  total_packets?: number;
  unique_sources?: number;
  unique_destinations?: number;
  last_seen?: string | null;
}

export interface CloudFlowTalker {
  ip?: string;
  total_bytes?: number;
  total_packets?: number;
  flow_count?: number;
}

export interface CloudFlowTimelinePoint {
  bucket?: string;
  total_bytes?: number;
  total_packets?: number;
  flow_count?: number;
}

export interface CloudTrafficMetricSummary {
  sample_count?: number;
  metric_count?: number;
  resource_count?: number;
  total_value?: number;
  avg_value?: number;
  last_seen?: string | null;
}

export interface CloudTrafficMetricResource {
  resource_uid?: string;
  total_value?: number;
  avg_value?: number;
  sample_count?: number;
}

export interface CloudTrafficMetricTimelinePoint {
  bucket?: string;
  total_value?: number;
  avg_value?: number;
  sample_count?: number;
}

export interface CloudPolicyEffectiveView {
  resource_uid?: string;
  resource_name?: string;
  resource_type?: string;
  provider?: string;
  rule_count?: number;
  public_ingress_count?: number;
  open_egress_count?: number;
  deny_count?: number;
}

export interface CloudPolicyRule {
  resource_uid?: string;
  resource_name?: string;
  provider?: string;
  rule_uid?: string;
  rule_name?: string;
  priority?: number | string;
  direction?: string;
  action?: string;
  protocol?: string;
  port_expression?: string;
  source_selector?: string;
  destination_selector?: string;
}

export interface CloudSyncConfig {
  enabled?: boolean;
  interval_seconds?: number;
  lookback_minutes?: number;
}

export interface CloudSyncStatus {
  last_run_at?: string;
  source?: string;
  scope?: string;
  account_id?: number | null;
  account_name?: string;
  ingested?: number;
  errors?: unknown[];
  ok?: boolean;
}

export interface CloudSyncCursor {
  account_id?: number;
  account_name?: string;
  provider?: string;
  last_pull_end?: string;
  updated_at?: string;
}

export interface CloudSyncConfigResponse {
  config: CloudSyncConfig | null;
  status?: CloudSyncStatus | null;
}

export interface CloudValidateResult {
  valid?: boolean;
  message?: string;
  status?: string;
  missing_dependencies?: string[];
}

export interface CloudDiscoverResult {
  ok?: boolean;
  message?: string;
  requested_mode?: string;
  effective_mode?: string;
  fallback_used?: boolean;
}

export interface CloudPullResult {
  ok?: boolean;
  ingested?: number;
  total_ingested?: number;
  errors?: unknown[];
}

// ── Helpers ───────────────────────────────────────────────────────────────

function qs(params: object): string {
  const cleaned: Record<string, string> = {};
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue;
    cleaned[k] = String(v);
  }
  const search = new URLSearchParams(cleaned).toString();
  return search ? `?${search}` : '';
}

export interface CloudFilter {
  provider?: string;
  account_id?: number | null;
}

// ── Query hooks ───────────────────────────────────────────────────────────

// Scheduled sync writes new data in the background; without periodic refetch
// (focus-refetch is globally disabled) an open dashboard stays frozen forever.
// Interval refetches pause automatically while the tab is not focused.
const MONITOR_REFETCH_MS = 60_000;

export function useCloudProviders() {
  return useQuery({
    queryKey: ['cloud-providers'],
    queryFn: () => apiRequest<{ providers: CloudProvider[] }>('/cloud/providers'),
  });
}

export function useCloudAccounts(provider?: string) {
  return useQuery({
    queryKey: ['cloud-accounts', provider ?? ''],
    queryFn: () =>
      apiRequest<{ accounts: CloudAccount[] }>(`/cloud/accounts${qs({ provider })}`),
    refetchInterval: MONITOR_REFETCH_MS,
  });
}

export function useCloudTopology(filter: CloudFilter) {
  return useQuery({
    queryKey: ['cloud-topology', filter.provider ?? '', filter.account_id ?? ''],
    queryFn: () => apiRequest<CloudTopology>(`/cloud/topology${qs(filter)}`),
    refetchInterval: MONITOR_REFETCH_MS,
  });
}

export interface FlowAnalyticsParams extends CloudFilter {
  hours: number;
  direction?: 'src' | 'dst';
  limit?: number;
  bucket_minutes?: number;
}

export function useCloudFlowSummary(params: FlowAnalyticsParams) {
  return useQuery({
    queryKey: ['cloud-flow-summary', params],
    queryFn: () =>
      apiRequest<{ summary: CloudFlowSummary }>(`/cloud/flow-logs/summary${qs(params)}`),
    refetchInterval: MONITOR_REFETCH_MS,
  });
}

export function useCloudFlowTopTalkers(params: FlowAnalyticsParams) {
  return useQuery({
    queryKey: ['cloud-flow-talkers', params],
    queryFn: () =>
      apiRequest<{ talkers: CloudFlowTalker[] }>(`/cloud/flow-logs/top-talkers${qs(params)}`),
    refetchInterval: MONITOR_REFETCH_MS,
  });
}

export function useCloudFlowTimeline(params: FlowAnalyticsParams) {
  return useQuery({
    queryKey: ['cloud-flow-timeline', params],
    queryFn: () =>
      apiRequest<{ timeline: CloudFlowTimelinePoint[] }>(`/cloud/flow-logs/timeline${qs(params)}`),
    refetchInterval: MONITOR_REFETCH_MS,
  });
}

export function useCloudTrafficMetricSummary(params: FlowAnalyticsParams) {
  return useQuery({
    queryKey: ['cloud-traffic-summary', params],
    queryFn: () =>
      apiRequest<{ summary: CloudTrafficMetricSummary }>(
        `/cloud/traffic-metrics/summary${qs(params)}`,
      ),
    refetchInterval: MONITOR_REFETCH_MS,
  });
}

export function useCloudTrafficMetricTopResources(params: FlowAnalyticsParams) {
  return useQuery({
    queryKey: ['cloud-traffic-resources', params],
    queryFn: () =>
      apiRequest<{ resources: CloudTrafficMetricResource[] }>(
        `/cloud/traffic-metrics/top-resources${qs(params)}`,
      ),
    refetchInterval: MONITOR_REFETCH_MS,
  });
}

export function useCloudTrafficMetricTimeline(params: FlowAnalyticsParams) {
  return useQuery({
    queryKey: ['cloud-traffic-timeline', params],
    queryFn: () =>
      apiRequest<{ timeline: CloudTrafficMetricTimelinePoint[] }>(
        `/cloud/traffic-metrics/timeline${qs(params)}`,
      ),
    refetchInterval: MONITOR_REFETCH_MS,
  });
}

export interface PolicyParams extends CloudFilter {
  direction?: string;
  action?: string;
  resource_uid?: string;
  limit?: number;
}

export function useCloudPolicyEffective(params: PolicyParams) {
  return useQuery({
    queryKey: ['cloud-policy-effective', params],
    queryFn: () =>
      apiRequest<{ resources: CloudPolicyEffectiveView[] }>(
        `/cloud/policies/effective${qs(params)}`,
      ),
  });
}

export function useCloudPolicyRules(params: PolicyParams) {
  return useQuery({
    queryKey: ['cloud-policy-rules', params],
    queryFn: () =>
      apiRequest<{ rules: CloudPolicyRule[] }>(`/cloud/policies/rules${qs(params)}`),
  });
}

export function useCloudFlowSyncConfig() {
  return useQuery({
    queryKey: ['cloud-flow-sync-config'],
    queryFn: () => apiRequest<CloudSyncConfigResponse>('/cloud/flow-sync/config'),
    refetchInterval: MONITOR_REFETCH_MS,
  });
}

export function useCloudFlowSyncCursors() {
  return useQuery({
    queryKey: ['cloud-flow-sync-cursors'],
    queryFn: () => apiRequest<{ cursors: CloudSyncCursor[] }>('/cloud/flow-sync/cursors'),
    refetchInterval: MONITOR_REFETCH_MS,
  });
}

export function useCloudTrafficSyncConfig() {
  return useQuery({
    queryKey: ['cloud-traffic-sync-config'],
    queryFn: () => apiRequest<CloudSyncConfigResponse>('/cloud/traffic-sync/config'),
    refetchInterval: MONITOR_REFETCH_MS,
  });
}

export function useCloudTrafficSyncCursors() {
  return useQuery({
    queryKey: ['cloud-traffic-sync-cursors'],
    queryFn: () => apiRequest<{ cursors: CloudSyncCursor[] }>('/cloud/traffic-sync/cursors'),
    refetchInterval: MONITOR_REFETCH_MS,
  });
}

// ── Mutations ─────────────────────────────────────────────────────────────

interface AccountPayload {
  provider: string;
  name: string;
  account_identifier?: string;
  region_scope?: string;
  auth_type?: string;
  /** Omit on update to keep the stored (write-only) credentials. */
  auth_config?: Record<string, unknown>;
  /** Set true on update to explicitly wipe stored credentials. */
  clear_auth_config?: boolean;
  notes?: string;
  enabled?: boolean;
}

interface AccountMutationResult {
  ok: boolean;
  account: CloudAccount;
}

export function useCreateCloudAccount() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: AccountPayload) =>
      apiRequest<AccountMutationResult>('/cloud/accounts', { method: 'POST', body: data }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cloud-accounts'] });
    },
  });
}

export function useUpdateCloudAccount() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: AccountPayload }) =>
      apiRequest<AccountMutationResult>(`/cloud/accounts/${id}`, { method: 'PUT', body: data }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cloud-accounts'] });
    },
  });
}

export function useDeleteCloudAccount() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest<unknown>(`/cloud/accounts/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cloud-accounts'] });
      qc.invalidateQueries({ queryKey: ['cloud-topology'] });
    },
  });
}

export function useValidateCloudAccount() {
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest<CloudValidateResult>(`/cloud/accounts/${id}/validate`, {
        method: 'POST',
        body: { mode: 'live' },
      }),
  });
}

export function useDiscoverCloudAccount() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest<CloudDiscoverResult>(`/cloud/accounts/${id}/discover`, {
        method: 'POST',
        body: { mode: 'auto', include_hybrid_links: true },
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cloud-accounts'] });
      qc.invalidateQueries({ queryKey: ['cloud-topology'] });
      qc.invalidateQueries({ queryKey: ['cloud-policy-effective'] });
      qc.invalidateQueries({ queryKey: ['cloud-policy-rules'] });
    },
  });
}

export function useUpdateCloudFlowSyncConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: CloudSyncConfig) =>
      apiRequest<{ config: CloudSyncConfig }>('/cloud/flow-sync/config', {
        method: 'PUT',
        body: data,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cloud-flow-sync-config'] });
    },
  });
}

export function useTriggerCloudFlowPull() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (accountId?: number | null) =>
      apiRequest<CloudPullResult>(
        `/cloud/flow-sync/pull${qs({ account_id: accountId })}`,
        { method: 'POST' },
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cloud-flow-sync-cursors'] });
      qc.invalidateQueries({ queryKey: ['cloud-flow-summary'] });
      qc.invalidateQueries({ queryKey: ['cloud-flow-talkers'] });
      qc.invalidateQueries({ queryKey: ['cloud-flow-timeline'] });
    },
  });
}

export function useUpdateCloudTrafficSyncConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: CloudSyncConfig) =>
      apiRequest<{ config: CloudSyncConfig }>('/cloud/traffic-sync/config', {
        method: 'PUT',
        body: data,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cloud-traffic-sync-config'] });
    },
  });
}

export function useTriggerCloudTrafficPull() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (accountId?: number | null) =>
      apiRequest<CloudPullResult>(
        `/cloud/traffic-sync/pull${qs({ account_id: accountId })}`,
        { method: 'POST' },
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cloud-traffic-sync-cursors'] });
      qc.invalidateQueries({ queryKey: ['cloud-traffic-summary'] });
      qc.invalidateQueries({ queryKey: ['cloud-traffic-resources'] });
      qc.invalidateQueries({ queryKey: ['cloud-traffic-timeline'] });
    },
  });
}
