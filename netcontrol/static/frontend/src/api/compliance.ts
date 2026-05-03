import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

// ── Types ──────────────────────────────────────────────────────────────────

export interface ComplianceSummary {
  total_profiles?: number;
  active_assignments?: number;
  hosts_scanned?: number;
  hosts_non_compliant?: number;
  last_scan_at?: string | null;
}

export interface ComplianceProfile {
  id: number;
  name: string;
  description?: string;
  severity: 'low' | 'medium' | 'high' | 'critical' | string;
  rules?: string;
  assignment_count?: number;
}

export interface ComplianceAssignment {
  id: number;
  profile_id: number;
  profile_name?: string;
  group_id: number;
  group_name?: string;
  credential_id?: number;
  enabled: boolean;
  interval_seconds: number;
  last_scan_at?: string | null;
  host_count?: number;
}

export interface ComplianceScanResult {
  id: number;
  hostname?: string;
  ip_address?: string;
  profile_name?: string;
  status: string;
  passed_rules: number;
  failed_rules: number;
  total_rules: number;
  scanned_at?: string;
  findings?: string;
}

export interface ComplianceHostStatus {
  hostname?: string;
  ip_address?: string;
  profile_name?: string;
  status: string;
  passed_rules: number;
  total_rules: number;
  scanned_at?: string;
}

export interface ComplianceFinding {
  name: string;
  type?: string;
  pattern?: string;
  detail?: string;
  passed: boolean;
  remediation?: string[];
}

export interface InventoryGroup {
  id: number;
  name: string;
  hosts?: { id: number; hostname: string; ip_address: string }[];
}

export interface Credential {
  id: number;
  name: string;
}

export interface RunScanResult {
  id?: number;
  status: string;
  passed_rules?: number;
  failed_rules?: number;
  total_rules?: number;
}

export interface RunScanBulkResult {
  hosts_scanned: number;
  violations: number;
  errors: number;
}

export interface RemediationResult {
  rule: string;
  rule_now_passes: boolean;
  rescan_id: number;
  rescan_passed: number;
  rescan_total: number;
}

// ── Queries ────────────────────────────────────────────────────────────────

export function useComplianceSummary() {
  return useQuery<ComplianceSummary>({
    queryKey: ['compliance-summary'],
    queryFn: () => apiRequest('/compliance/summary'),
  });
}

export function useComplianceProfiles() {
  return useQuery<ComplianceProfile[]>({
    queryKey: ['compliance-profiles'],
    queryFn: () => apiRequest('/compliance/profiles'),
  });
}

export function useComplianceProfile(id: number | null) {
  return useQuery<ComplianceProfile>({
    queryKey: ['compliance-profile', id],
    queryFn: () => apiRequest(`/compliance/profiles/${id}`),
    enabled: id != null,
  });
}

export function useComplianceAssignments(profileId?: number) {
  const qs = profileId ? `?profile_id=${profileId}` : '';
  return useQuery<ComplianceAssignment[]>({
    queryKey: ['compliance-assignments', profileId ?? 'all'],
    queryFn: () => apiRequest(`/compliance/assignments${qs}`),
  });
}

export function useComplianceScanResults(limit = 200) {
  return useQuery<ComplianceScanResult[]>({
    queryKey: ['compliance-results', limit],
    queryFn: () => apiRequest(`/compliance/results?limit=${limit}`),
  });
}

export function useComplianceScanResult(id: number | null) {
  return useQuery<ComplianceScanResult>({
    queryKey: ['compliance-result', id],
    queryFn: () => apiRequest(`/compliance/results/${id}`),
    enabled: id != null,
  });
}

export function useComplianceHostStatus() {
  return useQuery<ComplianceHostStatus[]>({
    queryKey: ['compliance-host-status'],
    queryFn: () => apiRequest('/compliance/status'),
  });
}

export function useInventoryGroups(includeHosts = false) {
  return useQuery<InventoryGroup[]>({
    queryKey: ['inventory-groups', includeHosts],
    queryFn: () =>
      apiRequest(includeHosts ? '/inventory?include_hosts=true' : '/inventory'),
  });
}

export function useCredentials() {
  return useQuery<Credential[]>({
    queryKey: ['credentials'],
    queryFn: () => apiRequest('/credentials'),
  });
}

// ── Mutations ──────────────────────────────────────────────────────────────

function invalidateCompliance(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: ['compliance-summary'] });
  qc.invalidateQueries({ queryKey: ['compliance-profiles'] });
  qc.invalidateQueries({ queryKey: ['compliance-assignments'] });
  qc.invalidateQueries({ queryKey: ['compliance-results'] });
  qc.invalidateQueries({ queryKey: ['compliance-host-status'] });
}

export interface ProfilePayload {
  name: string;
  description?: string;
  severity: string;
  rules: unknown[];
}

export function useCreateProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: ProfilePayload) =>
      apiRequest('/compliance/profiles', { method: 'POST', body: data }),
    onSuccess: () => invalidateCompliance(qc),
  });
}

export function useUpdateProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: ProfilePayload }) =>
      apiRequest(`/compliance/profiles/${id}`, { method: 'PUT', body: data }),
    onSuccess: () => invalidateCompliance(qc),
  });
}

export function useDeleteProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/compliance/profiles/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateCompliance(qc),
  });
}

export interface AssignmentPayload {
  profile_id: number;
  group_id: number;
  credential_id: number;
  interval_seconds: number;
}

export function useCreateAssignment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: AssignmentPayload) =>
      apiRequest('/compliance/assignments', { method: 'POST', body: data }),
    onSuccess: () => invalidateCompliance(qc),
  });
}

export function useUpdateAssignment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: Partial<AssignmentPayload & { enabled: boolean }> }) =>
      apiRequest(`/compliance/assignments/${id}`, { method: 'PUT', body: data }),
    onSuccess: () => invalidateCompliance(qc),
  });
}

export function useDeleteAssignment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/compliance/assignments/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateCompliance(qc),
  });
}

export function useRunScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: { host_id: number; profile_id: number; credential_id: number }) =>
      apiRequest<RunScanResult>('/compliance/scan', { method: 'POST', body: data }),
    onSuccess: () => invalidateCompliance(qc),
  });
}

export function useRunScanBulk() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: { profile_id: number; credential_id: number; host_ids: number[] }) =>
      apiRequest<RunScanBulkResult>('/compliance/scan-bulk', { method: 'POST', body: data }),
    onSuccess: () => invalidateCompliance(qc),
  });
}

export function useScanAssignmentNow() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (assignmentId: number) =>
      apiRequest<RunScanBulkResult>(`/compliance/assignments/${assignmentId}/scan-now`, {
        method: 'POST',
      }),
    onSuccess: () => invalidateCompliance(qc),
  });
}

export function useLoadBuiltinProfiles() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiRequest<{ loaded: number; skipped: number; total_available: number }>(
        '/compliance/profiles/load-builtin',
        { method: 'POST' },
      ),
    onSuccess: () => invalidateCompliance(qc),
  });
}

export function useRemediateFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: {
      result_id: number;
      rule_name: string;
      credential_id: number;
      dry_run?: boolean;
    }) =>
      apiRequest<RemediationResult>('/compliance/remediate', {
        method: 'POST',
        body: data,
      }),
    onSuccess: () => invalidateCompliance(qc),
  });
}
