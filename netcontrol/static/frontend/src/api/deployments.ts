import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

// ── Types ──────────────────────────────────────────────────────────────────

export type DeploymentStatus =
  | 'planning'
  | 'pre-check'
  | 'executing'
  | 'post-check'
  | 'completed'
  | 'failed'
  | 'rolled-back'
  | 'rolling-back'
  | 'verifying'
  | 'verified'
  | 'verification_failed'
  | string;

export interface DeploymentSummary {
  total?: number;
  completed?: number;
  active?: number;
  rolled_back?: number;
  failed?: number;
}

export interface Deployment {
  id: number;
  name: string;
  description?: string | null;
  group_id?: number | null;
  group_name?: string | null;
  credential_id?: number | null;
  change_type?: string | null;
  status: DeploymentStatus;
  rollback_status?: string | null;
  proposed_commands?: string | null;
  template_id?: number | null;
  risk_analysis_id?: number | null;
  host_ids?: string | null;
  created_at?: string | null;
  created_by?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
}

export interface DeploymentCheckpoint {
  id: number;
  deployment_id: number;
  host_id?: number | null;
  hostname?: string | null;
  ip_address?: string | null;
  phase: 'pre' | 'post' | 'rollback' | 'verify' | string;
  check_type: string;
  status: 'passed' | 'failed' | string;
  result?: string | null;
  executed_at?: string | null;
  created_at?: string | null;
}

export interface DeploymentSnapshot {
  id: number;
  deployment_id: number;
  host_id?: number | null;
  hostname?: string | null;
  phase: 'pre' | 'post' | string;
  created_at?: string | null;
}

export interface DeploymentDetail extends Deployment {
  checkpoints?: DeploymentCheckpoint[];
  snapshots?: DeploymentSnapshot[];
}

export interface DeploymentJobStartResult {
  job_id: string;
  deployment_id: number;
}

export interface DeploymentCreatePayload {
  name: string;
  description?: string;
  group_id: number;
  credential_id: number;
  change_type: string;
  proposed_commands: string[];
  template_id?: number | null;
  risk_analysis_id?: number | null;
  host_ids?: number[];
}

export interface DeploymentDriftEvent {
  host_id?: number;
  hostname?: string | null;
  detected_at?: string | null;
  diff_lines_added?: number;
  diff_lines_removed?: number;
}

export interface DeploymentAlert {
  id?: number;
  host_id?: number;
  hostname?: string | null;
  metric?: string;
  alert_type?: string;
  severity?: string;
  message?: string;
  value?: number | null;
  created_at?: string | null;
}

export interface DeploymentAuditEvent {
  timestamp?: string | null;
  action: string;
  detail?: string | null;
}

export interface DeploymentCorrelation {
  deployment: Deployment;
  checkpoints: DeploymentCheckpoint[];
  drift_events: DeploymentDriftEvent[];
  alerts: DeploymentAlert[];
  audit_trail: DeploymentAuditEvent[];
  time_window: { start?: string | null; end?: string | null };
}

// ── Queries ────────────────────────────────────────────────────────────────

export function useDeploymentSummary() {
  return useQuery<DeploymentSummary>({
    queryKey: ['deployment-summary'],
    queryFn: () => apiRequest('/deployments/summary'),
  });
}

export function useDeployments(limit = 200) {
  return useQuery<Deployment[]>({
    queryKey: ['deployments', limit],
    queryFn: () => apiRequest(`/deployments?limit=${limit}`),
  });
}

export function useDeployment(id: number | null) {
  return useQuery<DeploymentDetail>({
    queryKey: ['deployment', id],
    queryFn: () => apiRequest(`/deployments/${id}`),
    enabled: id != null,
  });
}

export function useDeploymentCorrelation(id: number | null) {
  return useQuery<DeploymentCorrelation>({
    queryKey: ['deployment-correlation', id],
    queryFn: () => apiRequest(`/deployments/${id}/correlation`),
    enabled: id != null,
  });
}

// ── Mutations ──────────────────────────────────────────────────────────────

function invalidateDeployments(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: ['deployment-summary'] });
  qc.invalidateQueries({ queryKey: ['deployments'] });
}

export function useCreateDeployment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: DeploymentCreatePayload) =>
      apiRequest<{ id: number; status: string }>('/deployments', {
        method: 'POST',
        body: data,
      }),
    onSuccess: () => invalidateDeployments(qc),
  });
}

export function useExecuteDeployment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest<DeploymentJobStartResult>(`/deployments/${id}/execute`, {
        method: 'POST',
      }),
    onSuccess: () => invalidateDeployments(qc),
  });
}

export function useRollbackDeployment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest<DeploymentJobStartResult>(`/deployments/${id}/rollback`, {
        method: 'POST',
      }),
    onSuccess: () => invalidateDeployments(qc),
  });
}

export function useDeleteDeployment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/deployments/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateDeployments(qc),
  });
}
