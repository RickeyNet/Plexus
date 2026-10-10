import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

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
