import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

export type AuditSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface AuditRunSummary {
  id: number;
  status: string;
  trigger: string;
  started_at?: string | null;
  finished_at?: string | null;
  host_count: number;
  findings_total: number;
  findings_critical: number;
  findings_high: number;
  findings_medium: number;
  findings_low: number;
  findings_info: number;
}

export interface AuditFinding {
  id: number;
  run_id: number;
  host_id?: number | null;
  rule_id: string;
  category: string;
  severity: AuditSeverity;
  cis_control?: string;
  title: string;
  detail?: string;
  evidence?: Record<string, unknown>;
  created_at?: string;
}

export function useAuditRuns() {
  return useQuery<{ runs: AuditRunSummary[] }>({
    queryKey: ['audit', 'runs'],
    queryFn: () => apiRequest('/audit/runs'),
  });
}

export function useAuditFindings(runId: number | null) {
  return useQuery<{ findings: AuditFinding[] }>({
    queryKey: ['audit', 'findings', runId],
    queryFn: () => apiRequest(`/audit/runs/${runId}/findings`),
    enabled: runId != null,
  });
}

export function useTriggerAuditRun() {
  const qc = useQueryClient();
  return useMutation<AuditRunSummary, Error, void>({
    mutationFn: () =>
      apiRequest('/audit/runs', {
        method: 'POST',
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['audit', 'runs'] });
    },
  });
}
