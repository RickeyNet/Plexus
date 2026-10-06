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
  qc.invalidateQueries({ queryKey: ['compliance-meraki'] });
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

// ── Meraki organizations ───────────────────────────────────────────────────
//
// Profiles may carry rules of type "meraki" naming a check against the
// Dashboard API configuration of an organization (DHCP server policy for
// DHCP snooping, port access policies for port security, BPDU guard, ...).
// They are scanned per organization as background jobs, never over SSH.

export type MerakiTargetKind = 'org' | 'network' | 'device' | 'ssid';

export interface MerakiCheck {
  id: string;
  name: string;
  scope: MerakiTargetKind;
  category: string;
  category_label: string;
  description: string;
  ios_equivalent: string;
  params: Record<string, unknown>;
  products: string[];
  /** The profile rule that selects this check with its default parameters. */
  rule: Record<string, unknown>;
}

export interface MerakiComplianceOrg {
  id: number;
  name: string;
  org_id: string;
  has_api_key: boolean;
  is_sample: boolean;
  scanning: boolean;
  last_build_at?: string | null;
}

export interface MerakiAssignment {
  id: number;
  profile_id: number;
  profile_name?: string;
  profile_severity?: string;
  org_ref: number;
  org_name?: string;
  org_identifier?: string;
  org_has_api_key?: boolean;
  enabled: boolean;
  interval_seconds: number;
  last_scan_at?: string | null;
  last_scan_status?: string;
  last_scan_message?: string;
  scanning?: boolean;
}

export interface MerakiResult {
  id: number;
  scan_id: string;
  assignment_id?: number | null;
  profile_id: number;
  profile_name?: string;
  org_ref: number;
  org_name?: string;
  target_kind: MerakiTargetKind | string;
  target_id: string;
  target_name: string;
  network_id: string;
  network_name: string;
  model: string;
  serial: string;
  status: string;
  total_rules: number;
  passed_rules: number;
  failed_rules: number;
  unreadable_rules: number;
  scanned_at?: string;
}

export interface MerakiFinding {
  name: string;
  type?: string;
  check: string;
  scope: string;
  category: string;
  ios_equivalent: string;
  passed: boolean | null;
  detail: string;
  evidence: string[];
  unreadable: boolean;
}

export interface MerakiResultDetail extends MerakiResult {
  findings: MerakiFinding[];
}

export interface MerakiScanResult {
  scan_id: string;
  org_ref: number;
  org_name: string;
  profile_id: number;
  profile_name: string;
  status: string;
  message: string;
  collection_warnings: number;
  duration_seconds: number;
  targets: number;
  compliant: number;
  non_compliant: number;
  errors: number;
}

export interface MerakiScanJob {
  job_id: string;
  status: 'running' | 'completed' | 'partial' | 'failed' | string;
  progress: Record<string, unknown>;
  result: MerakiScanResult | null;
  error: string | null;
}

export interface MerakiSummary {
  active_assignments: number;
  targets_scanned: number;
  targets_non_compliant: number;
  targets_error: number;
  last_scan_at: string | null;
  scans_running: number;
}

export function useMerakiChecks() {
  return useQuery<{ checks: MerakiCheck[]; categories: Record<string, string> }>({
    queryKey: ['compliance-meraki', 'checks'],
    queryFn: () => apiRequest('/compliance/meraki/checks'),
    staleTime: 10 * 60 * 1000,
  });
}

export function useMerakiComplianceOrgs() {
  return useQuery<MerakiComplianceOrg[]>({
    queryKey: ['compliance-meraki', 'orgs'],
    queryFn: () => apiRequest('/compliance/meraki/orgs'),
  });
}

export function useMerakiAssignments(profileId?: number) {
  const qs = profileId ? `?profile_id=${profileId}` : '';
  return useQuery<MerakiAssignment[]>({
    queryKey: ['compliance-meraki', 'assignments', profileId ?? 'all'],
    queryFn: () => apiRequest(`/compliance/meraki/assignments${qs}`),
    // Keeps the "Scanning" state honest for scans started elsewhere.
    refetchInterval: (query) => (query.state.data?.some((a) => a.scanning) ? 4000 : false),
  });
}

export function useMerakiResults(limit = 200) {
  return useQuery<MerakiResult[]>({
    queryKey: ['compliance-meraki', 'results', limit],
    queryFn: () => apiRequest(`/compliance/meraki/results?limit=${limit}`),
  });
}

export function useMerakiResult(id: number | null) {
  return useQuery<MerakiResultDetail>({
    queryKey: ['compliance-meraki', 'result', id],
    queryFn: () => apiRequest(`/compliance/meraki/results/${id}`),
    enabled: id != null,
  });
}

export function useMerakiStatus() {
  return useQuery<MerakiResult[]>({
    queryKey: ['compliance-meraki', 'status'],
    queryFn: () => apiRequest('/compliance/meraki/status'),
  });
}

export function useMerakiSummary() {
  return useQuery<MerakiSummary>({
    queryKey: ['compliance-meraki', 'summary'],
    queryFn: () => apiRequest('/compliance/meraki/summary'),
  });
}

export function useMerakiScanJob(jobId: string | null) {
  const qc = useQueryClient();
  return useQuery<MerakiScanJob>({
    queryKey: ['compliance-meraki', 'scan-job', jobId],
    queryFn: async () => {
      const job = await apiRequest<MerakiScanJob>(`/compliance/meraki/scans/${jobId}`);
      // The job wrote results when it settled; refresh every list that shows them.
      if (job.status !== 'running') invalidateCompliance(qc);
      return job;
    },
    enabled: jobId != null,
    // A scan is a background job with no push channel; poll until it settles
    // (or the job record is gone, which surfaces as an error).
    refetchInterval: (query) => {
      if (query.state.status === 'error') return false;
      return !query.state.data || query.state.data.status === 'running' ? 1500 : false;
    },
    retry: false,
  });
}

export interface MerakiAssignmentPayload {
  profile_id: number;
  org_ref: number;
  interval_seconds: number;
}

export function useCreateMerakiAssignment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: MerakiAssignmentPayload) =>
      apiRequest<{ id: number }>('/compliance/meraki/assignments', { method: 'POST', body: data }),
    onSuccess: () => invalidateCompliance(qc),
  });
}

export function useUpdateMerakiAssignment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: { enabled?: boolean; interval_seconds?: number } }) =>
      apiRequest(`/compliance/meraki/assignments/${id}`, { method: 'PUT', body: data }),
    onSuccess: () => invalidateCompliance(qc),
  });
}

export function useDeleteMerakiAssignment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/compliance/meraki/assignments/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateCompliance(qc),
  });
}

export function useRunMerakiScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: { profile_id: number; org_ref: number }) =>
      apiRequest<{ job_id: string; status: string }>('/compliance/meraki/scan', {
        method: 'POST',
        body: data,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['compliance-meraki', 'assignments'] }),
  });
}

export function useScanMerakiAssignmentNow() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (assignmentId: number) =>
      apiRequest<{ job_id: string; status: string }>(
        `/compliance/meraki/assignments/${assignmentId}/scan-now`,
        { method: 'POST' },
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['compliance-meraki', 'assignments'] }),
  });
}

export function useDeleteMerakiResult() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => apiRequest(`/compliance/meraki/results/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateCompliance(qc),
  });
}
