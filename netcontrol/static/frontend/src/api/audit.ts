import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

export type AuditSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface AuditRunSummary {
  id: number;
  status: string;
  trigger: string;
  schedule_id?: number | null;
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

export interface AuditSchedule {
  id: number;
  name: string;
  schedule: string;
  enabled: boolean;
  last_run_at?: string | null;
  created_by?: string;
  created_at?: string;
  updated_at?: string;
}

export interface AuditSchedulePayload {
  name: string;
  schedule: string;
  enabled?: boolean;
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

// ── Schedules (Phase 5) ────────────────────────────────────────────────────

export function useAuditSchedules() {
  return useQuery<{ schedules: AuditSchedule[] }>({
    queryKey: ['audit', 'schedules'],
    queryFn: () => apiRequest('/audit/schedules'),
  });
}

export function useCreateAuditSchedule() {
  const qc = useQueryClient();
  return useMutation<AuditSchedule, Error, AuditSchedulePayload>({
    mutationFn: (payload) =>
      apiRequest('/audit/schedules', {
        method: 'POST',
        body: payload,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['audit', 'schedules'] });
    },
  });
}

export function useUpdateAuditSchedule() {
  const qc = useQueryClient();
  return useMutation<
    AuditSchedule,
    Error,
    { id: number; payload: Partial<AuditSchedulePayload> }
  >({
    mutationFn: ({ id, payload }) =>
      apiRequest(`/audit/schedules/${id}`, {
        method: 'PUT',
        body: payload,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['audit', 'schedules'] });
    },
  });
}

export function useDeleteAuditSchedule() {
  const qc = useQueryClient();
  return useMutation<void, Error, number>({
    mutationFn: (id) =>
      apiRequest(`/audit/schedules/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['audit', 'schedules'] });
    },
  });
}

export function useRunScheduleNow() {
  const qc = useQueryClient();
  return useMutation<
    { run_id: number; schedule_id: number; status: string },
    Error,
    number
  >({
    mutationFn: (id) =>
      apiRequest(`/audit/schedules/${id}/run-now`, { method: 'POST' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['audit', 'runs'] });
    },
  });
}

// ── Overrides (Phase 6) ───────────────────────────────────────────────────
//
// An override suppresses a (rule_id, host_id?) pair from future runs. The
// mute/accept_risk distinction is recorded for the audit trail but both
// modes hide the finding from the persisted set.

export type AuditOverrideMode = 'mute' | 'accept_risk';

export interface AuditOverride {
  id: number;
  rule_id: string;
  host_id: number | null;
  mode: AuditOverrideMode;
  reason: string;
  created_by: string;
  created_at?: string;
  expires_at?: string | null;
}

export interface AuditOverridePayload {
  rule_id: string;
  host_id?: number | null;
  mode?: AuditOverrideMode;
  reason?: string;
  created_by?: string;
  expires_at?: string | null;
}

export function useAuditOverrides() {
  return useQuery<{ overrides: AuditOverride[] }>({
    queryKey: ['audit', 'overrides'],
    queryFn: () => apiRequest('/audit/overrides'),
  });
}

export function useCreateAuditOverride() {
  const qc = useQueryClient();
  return useMutation<AuditOverride, Error, AuditOverridePayload>({
    mutationFn: (payload) =>
      apiRequest('/audit/overrides', {
        method: 'POST',
        body: payload,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['audit', 'overrides'] });
    },
  });
}

export function useDeleteAuditOverride() {
  const qc = useQueryClient();
  return useMutation<void, Error, number>({
    mutationFn: (id) =>
      apiRequest(`/audit/overrides/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['audit', 'overrides'] });
    },
  });
}
