import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

// ── Types ──────────────────────────────────────────────────────────────────

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical' | 'unknown';

export interface RiskAnalysisSummary {
  total?: number;
  high_risk?: number;
  approved?: number;
  pending?: number;
  last_analysis_at?: string | null;
}

export interface RiskAnalysis {
  id: number;
  change_type?: string;
  host_id?: number | null;
  hostname?: string | null;
  ip_address?: string | null;
  group_id?: number | null;
  group_name?: string | null;
  risk_level: RiskLevel | string;
  risk_score: number;
  proposed_commands?: string | null;
  proposed_diff?: string | null;
  current_config?: string | null;
  simulated_config?: string | null;
  analysis?: string | null;
  compliance_impact?: string | null;
  affected_areas?: string | null;
  approved?: boolean | number;
  approved_by?: string | null;
  created_at?: string | null;
  created_by?: string | null;
}

export interface RiskAnalysisHostResult {
  host_id?: number;
  hostname?: string;
  ip_address?: string;
  status?: string;
  error?: string;
  risk_level: RiskLevel | string;
  risk_score: number;
  affected_areas?: string[];
}

export interface RiskAnalysisRunResult {
  id: number;
  risk_level: RiskLevel | string;
  risk_score: number;
  hosts_analyzed: number;
  total_compliance_violations: number;
  affected_areas: string[];
  host_results: RiskAnalysisHostResult[];
}

export interface OfflineRiskAnalysisResult {
  id: number;
  risk_level: RiskLevel | string;
  risk_score: number;
  proposed_diff?: string;
  simulated_config?: string;
  analysis?: {
    risk_factors?: string[];
    change_volume?: { total_commands?: number; diff_lines_added?: number; diff_lines_removed?: number };
    affected_areas?: { label: string }[];
  };
  affected_areas: string[];
}

export interface RiskAnalysisRunPayload {
  change_type: string;
  group_id?: number;
  host_id?: number;
  host_ids?: number[];
  credential_id: number;
  proposed_commands: string[];
  template_id?: number;
}

export interface OfflineRiskAnalysisPayload {
  change_type: string;
  current_config: string;
  proposed_commands: string[];
}

export interface RiskTemplate {
  id: number;
  name: string;
  content?: string;
}

export interface RiskCredential {
  id: number;
  name: string;
}

export interface RiskInventoryGroup {
  id: number;
  name: string;
}

// ── Queries ────────────────────────────────────────────────────────────────

export function useRiskAnalysisSummary() {
  return useQuery<RiskAnalysisSummary>({
    queryKey: ['risk-analysis-summary'],
    queryFn: () => apiRequest('/risk-analysis/summary'),
  });
}

export function useRiskAnalyses(limit = 200) {
  return useQuery<RiskAnalysis[]>({
    queryKey: ['risk-analyses', limit],
    queryFn: () => apiRequest(`/risk-analysis?limit=${limit}`),
  });
}

export function useRiskAnalysis(id: number | null) {
  return useQuery<RiskAnalysis>({
    queryKey: ['risk-analysis', id],
    queryFn: () => apiRequest(`/risk-analysis/${id}`),
    enabled: id != null,
  });
}

export function useRiskTemplates() {
  return useQuery<RiskTemplate[]>({
    queryKey: ['templates'],
    queryFn: () => apiRequest('/templates'),
  });
}

export function useRiskCredentials() {
  return useQuery<RiskCredential[]>({
    queryKey: ['credentials'],
    queryFn: () => apiRequest('/credentials'),
  });
}

export function useRiskInventoryGroups() {
  return useQuery<RiskInventoryGroup[]>({
    queryKey: ['inventory-groups', false],
    queryFn: () => apiRequest('/inventory'),
  });
}

// ── Mutations ──────────────────────────────────────────────────────────────

function invalidateRiskAnalyses(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: ['risk-analysis-summary'] });
  qc.invalidateQueries({ queryKey: ['risk-analyses'] });
}

export function useRunRiskAnalysis() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: RiskAnalysisRunPayload) =>
      apiRequest<RiskAnalysisRunResult>('/risk-analysis/analyze', {
        method: 'POST',
        body: data,
      }),
    onSuccess: () => invalidateRiskAnalyses(qc),
  });
}

export function useRunOfflineRiskAnalysis() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: OfflineRiskAnalysisPayload) =>
      apiRequest<OfflineRiskAnalysisResult>('/risk-analysis/analyze-offline', {
        method: 'POST',
        body: data,
      }),
    onSuccess: () => invalidateRiskAnalyses(qc),
  });
}

export function useApproveRiskAnalysis() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/risk-analysis/${id}/approve`, { method: 'POST' }),
    onSuccess: () => invalidateRiskAnalyses(qc),
  });
}

export function useDeleteRiskAnalysis() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/risk-analysis/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateRiskAnalyses(qc),
  });
}
