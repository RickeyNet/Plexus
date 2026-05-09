import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

// ── Capacity Planning ──────────────────────────────────────────────────────

export interface CapacityPlanningPoint {
  hostname?: string;
  host_id?: number;
  period_start: string;
  val_avg?: number | null;
  value?: number | null;
}

export interface CapacityPlanningHostResult {
  host_id?: number;
  hostname?: string;
  trend?: { slope: number; intercept: number } | null;
  threshold_eta?: { current_value: number; days_until: number; date: string } | null;
  projection?: { date: string; value: number }[];
}

export interface CapacityPlanningResult {
  count: number;
  threshold?: number;
  data?: CapacityPlanningPoint[];
  per_host?: CapacityPlanningHostResult[];
}

export interface CapacityPlanningParams {
  metric: string;
  range: string;
  group?: string;
  projectionDays?: number;
  threshold?: number;
}

export function useCapacityPlanning(params: CapacityPlanningParams) {
  const qs = new URLSearchParams();
  qs.set('metric', params.metric);
  qs.set('range', params.range);
  if (params.group) qs.set('group', params.group);
  if (params.projectionDays != null) qs.set('projection_days', String(params.projectionDays));
  if (params.threshold != null) qs.set('threshold', String(params.threshold));
  return useQuery<CapacityPlanningResult>({
    queryKey: ['reports-capacity-planning', params.metric, params.range, params.group ?? '', params.projectionDays ?? 30, params.threshold ?? null],
    queryFn: () => apiRequest(`/metrics/capacity-planning?${qs}`),
  });
}

// ── Availability ───────────────────────────────────────────────────────────

export type AvailabilityState = 'up' | 'down' | 'unknown' | string;

export interface AvailabilityHostSummary {
  host_id: number;
  hostname?: string;
  current_state?: AvailabilityState;
  uptime_pct?: number | null;
  total_up_seconds?: number | null;
  total_down_seconds?: number | null;
  transition_count?: number | null;
}

export interface AvailabilitySummary {
  hosts?: AvailabilityHostSummary[];
}

export interface AvailabilityOutage {
  host_id: number;
  hostname?: string;
  down_at?: string | null;
  up_at?: string | null;
  duration_seconds?: number | null;
}

export interface AvailabilityTransition {
  host_id: number;
  hostname?: string;
  entity_type?: string;
  entity_id?: string;
  old_state?: AvailabilityState;
  new_state?: AvailabilityState;
  transition_at?: string | null;
}

export function useAvailabilitySummary(groupId: string | null, days: number) {
  const qs = new URLSearchParams({ days: String(days) });
  if (groupId) qs.set('group_id', groupId);
  return useQuery<AvailabilitySummary>({
    queryKey: ['reports-availability-summary', groupId ?? '', days],
    queryFn: () => apiRequest(`/availability/summary?${qs}`),
  });
}

export function useAvailabilityOutages(groupId: string | null, days: number, limit = 200) {
  const qs = new URLSearchParams({ days: String(days), limit: String(limit) });
  if (groupId) qs.set('group_id', groupId);
  return useQuery<{ outages: AvailabilityOutage[] } | AvailabilityOutage[]>({
    queryKey: ['reports-availability-outages', groupId ?? '', days, limit],
    queryFn: () => apiRequest(`/availability/outages?${qs}`),
  });
}

export function useAvailabilityTransitions(limit = 200) {
  const qs = new URLSearchParams({ entity_type: 'host', limit: String(limit) });
  return useQuery<{ transitions: AvailabilityTransition[] } | AvailabilityTransition[]>({
    queryKey: ['reports-availability-transitions', limit],
    queryFn: () => apiRequest(`/availability/transitions?${qs}`),
  });
}

// ── Syslog Events ──────────────────────────────────────────────────────────

export interface SyslogEvent {
  timestamp?: string;
  host_id?: number;
  hostname?: string;
  severity?: string;
  event_type?: string;
  message?: string;
  event_data?: string;
}

export interface SyslogEventsParams {
  hostId?: number;
  severity?: string;
  eventType?: string;
  limit?: number;
}

export function useSyslogEvents(params: SyslogEventsParams) {
  const qs = new URLSearchParams();
  qs.set('event_type', params.eventType || 'syslog');
  if (params.hostId != null) qs.set('host_id', String(params.hostId));
  if (params.severity) qs.set('severity', params.severity);
  if (params.limit != null) qs.set('limit', String(params.limit));
  return useQuery<{ events: SyslogEvent[] } | SyslogEvent[]>({
    queryKey: ['syslog-events', params.hostId ?? null, params.severity ?? '', params.eventType ?? 'syslog', params.limit ?? 500],
    queryFn: () => apiRequest(`/metrics/events?${qs}`),
  });
}

// ── Report Runs ────────────────────────────────────────────────────────────

export interface ReportRun {
  id: number;
  report_type?: string;
  status?: string;
  row_count?: number;
  started_at?: string;
}

export interface ReportArtifact {
  id: number;
  artifact_type?: string;
  media_type?: string;
  file_name?: string;
  size_bytes?: number;
}

export interface ReportGeneratePayload {
  report_type: string;
  parameters?: Record<string, unknown>;
  persist_artifacts?: boolean;
}

export interface ReportGenerateResult {
  run_id?: number;
  rows: Record<string, unknown>[];
  artifacts?: ReportArtifact[];
}

export function useReportRuns() {
  return useQuery<{ runs: ReportRun[] } | ReportRun[]>({
    queryKey: ['report-runs'],
    queryFn: () => apiRequest('/reports/runs'),
  });
}

export function useReportRunArtifacts(runId: number | null, limit = 100) {
  return useQuery<{ artifacts: ReportArtifact[] }>({
    queryKey: ['report-run-artifacts', runId, limit],
    queryFn: () => apiRequest(`/reports/runs/${runId}/artifacts?limit=${limit}`),
    enabled: runId != null,
  });
}

export function useGenerateReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: ReportGeneratePayload) =>
      apiRequest<ReportGenerateResult>('/reports/generate', { method: 'POST', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['report-runs'] }),
  });
}

export function reportArtifactUrl(artifactId: number): string {
  return `/api/reports/artifacts/${artifactId}`;
}

// ── OID Profiles ───────────────────────────────────────────────────────────

export interface OidProfile {
  id: number;
  name: string;
  vendor?: string;
  device_type?: string;
  description?: string;
  oids_json?: string;
  is_default?: boolean;
}

export interface OidProfilePayload {
  name: string;
  vendor: string;
  device_type: string;
  description: string;
  oids_json: string;
}

export function useOidProfiles(vendor?: string | null) {
  const qs = vendor ? `?vendor=${encodeURIComponent(vendor)}` : '';
  return useQuery<{ profiles: OidProfile[] } | OidProfile[]>({
    queryKey: ['oid-profiles', vendor ?? ''],
    queryFn: () => apiRequest(`/oid-profiles${qs}`),
  });
}

export function useOidProfile(id: number | null) {
  return useQuery<OidProfile>({
    queryKey: ['oid-profile', id],
    queryFn: () => apiRequest(`/oid-profiles/${id}`),
    enabled: id != null,
  });
}

export function useCreateOidProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: OidProfilePayload) =>
      apiRequest('/oid-profiles', { method: 'POST', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['oid-profiles'] }),
  });
}

export function useUpdateOidProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: OidProfilePayload }) =>
      apiRequest(`/oid-profiles/${id}`, { method: 'PUT', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['oid-profiles'] }),
  });
}

export function useDeleteOidProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/oid-profiles/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['oid-profiles'] }),
  });
}

// ── Bandwidth Billing ──────────────────────────────────────────────────────

export interface BillingCircuit {
  id: number;
  name: string;
  customer?: string;
  host_id?: number;
  hostname?: string;
  if_index?: number;
  if_name?: string;
  commit_rate_bps?: number;
  burst_limit_bps?: number;
  cost_per_mbps?: number;
  currency?: string;
  billing_day?: number;
  billing_cycle?: string;
  enabled?: boolean | number;
  description?: string;
}

export interface BillingCircuitCreate {
  name: string;
  customer: string;
  host_id: number;
  if_index: number;
  if_name: string;
  commit_rate_bps: number;
  burst_limit_bps: number;
  cost_per_mbps: number;
  currency: string;
  billing_day: number;
  billing_cycle: string;
  description: string;
}

export interface BillingCircuitUpdate {
  name?: string;
  customer?: string;
  commit_rate_bps?: number;
  cost_per_mbps?: number;
  billing_day?: number;
  enabled?: number | boolean;
  description?: string;
}

export interface BillingPeriod {
  id: number;
  customer?: string;
  circuit_name?: string;
  hostname?: string;
  if_name?: string;
  period_start?: string;
  period_end?: string;
  p95_in_bps?: number;
  p95_out_bps?: number;
  p95_billing_bps?: number;
  commit_rate_bps?: number;
  overage_bps?: number;
  overage_cost?: number;
  total_samples?: number;
  status?: string;
}

export interface BillingPeriodSample {
  sampled_at: string;
  in_rate_bps?: number;
  out_rate_bps?: number;
}

export interface BillingPeriodUsage {
  period: BillingPeriod;
  circuit?: BillingCircuit;
  samples: BillingPeriodSample[];
}

export interface BillingSummary {
  total_circuits?: number;
  enabled_circuits?: number;
  total_periods?: number;
  overage_periods?: number;
  total_overage_cost?: number;
}

export interface BillingGeneratePayload {
  circuit_id?: number;
  period_start?: string;
  period_end?: string;
}

export interface BillingGenerateResult {
  count?: number;
  periods?: { status?: string }[];
}

function billingQuery(customer?: string): string {
  const qs = new URLSearchParams();
  if (customer) qs.set('customer', customer);
  const s = qs.toString();
  return s ? `?${s}` : '';
}

export function useBillingCircuits(customer?: string, enabledOnly?: boolean) {
  const qs = new URLSearchParams();
  if (customer) qs.set('customer', customer);
  if (enabledOnly) qs.set('enabled', 'true');
  const tail = qs.toString();
  return useQuery<{ circuits: BillingCircuit[] }>({
    queryKey: ['billing-circuits', customer ?? '', !!enabledOnly],
    queryFn: () => apiRequest(`/billing/circuits${tail ? '?' + tail : ''}`),
  });
}

export function useBillingCircuit(id: number | null) {
  return useQuery<BillingCircuit>({
    queryKey: ['billing-circuit', id],
    queryFn: () => apiRequest(`/billing/circuits/${id}`),
    enabled: id != null,
  });
}

export function useBillingCustomers() {
  return useQuery<{ customers: string[] }>({
    queryKey: ['billing-customers'],
    queryFn: () => apiRequest('/billing/customers'),
  });
}

export function useBillingSummary(customer?: string) {
  return useQuery<BillingSummary>({
    queryKey: ['billing-summary', customer ?? ''],
    queryFn: () => apiRequest(`/billing/summary${billingQuery(customer)}`),
  });
}

export function useBillingPeriods(customer?: string) {
  return useQuery<{ periods: BillingPeriod[] }>({
    queryKey: ['billing-periods', customer ?? ''],
    queryFn: () => apiRequest(`/billing/periods${billingQuery(customer)}`),
  });
}

export function useBillingPeriodUsage(id: number | null) {
  return useQuery<BillingPeriodUsage>({
    queryKey: ['billing-period-usage', id],
    queryFn: () => apiRequest(`/billing/periods/${id}/usage`),
    enabled: id != null,
  });
}

function invalidateBilling(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: ['billing-circuits'] });
  qc.invalidateQueries({ queryKey: ['billing-customers'] });
  qc.invalidateQueries({ queryKey: ['billing-summary'] });
  qc.invalidateQueries({ queryKey: ['billing-periods'] });
}

export function useCreateBillingCircuit() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: BillingCircuitCreate) =>
      apiRequest('/billing/circuits', { method: 'POST', body: data }),
    onSuccess: () => invalidateBilling(qc),
  });
}

export function useUpdateBillingCircuit() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: BillingCircuitUpdate }) =>
      apiRequest(`/billing/circuits/${id}`, { method: 'PUT', body: data }),
    onSuccess: () => invalidateBilling(qc),
  });
}

export function useDeleteBillingCircuit() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/billing/circuits/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateBilling(qc),
  });
}

export function useGenerateBilling() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: BillingGeneratePayload) =>
      apiRequest<BillingGenerateResult>('/billing/generate', { method: 'POST', body: data }),
    onSuccess: () => invalidateBilling(qc),
  });
}

export function billingExportUrl(customer?: string): string {
  return `/api/billing/export/periods${billingQuery(customer)}`;
}
