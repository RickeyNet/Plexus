import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

export interface LabEnvironment {
  id: number;
  name: string;
  description: string;
  owner_id: number | null;
  shared: number | boolean;
  active: number | boolean;
  created_at: string;
  updated_at: string;
  device_count?: number;
}

export interface LabDeviceSummary {
  id: number;
  environment_id: number;
  hostname: string;
  ip_address: string;
  device_type: string;
  model: string;
  source_host_id: number | null;
  notes: string;
  created_at: string;
  updated_at: string;
  config_size: number;
  run_count: number;
  runtime_kind?: string;
  runtime_status?: string;
  runtime_mgmt_address?: string;
  runtime_node_kind?: string;
  runtime_image?: string;
}

export interface LabDevice extends LabDeviceSummary {
  running_config: string;
  runtime_kind?: string;
  runtime_node_kind?: string;
  runtime_image?: string;
  runtime_status?: string;
  runtime_lab_name?: string;
  runtime_node_name?: string;
  runtime_mgmt_address?: string;
  runtime_credential_id?: number | null;
  runtime_error?: string;
  runtime_workdir?: string;
  runtime_started_at?: string | null;
}

export interface LabRuntimeStatus {
  available: boolean;
  binary: string | null;
  version: string | null;
  reason: string;
  allowed_node_kinds: string[];
}

export interface LabRuntimeEvent {
  id: number;
  lab_device_id: number;
  action: string;
  status: string;
  actor: string;
  detail: string;
  created_at: string;
}

export interface DeployRuntimeResult {
  status: string;
  lab_name: string;
  node_name: string;
  mgmt_ipv4: string;
  workdir: string;
}

export interface SimulateLiveResult {
  run_id: number;
  status: string;
  risk_score: number;
  risk_level: string;
  diff_text: string;
  diff_added: number;
  diff_removed: number;
  affected_areas: string[];
  post_config: string;
  push_output: string;
}

export interface LabRunSummary {
  id: number;
  lab_device_id: number;
  submitted_by: string;
  diff_added: number;
  diff_removed: number;
  risk_score: number;
  risk_level: string;
  status: string;
  promoted_deployment_id: number | null;
  created_at: string;
}

export interface LabRunDetail extends LabRunSummary {
  commands: string[];
  pre_config: string;
  post_config: string;
  diff_text: string;
  risk_detail: Record<string, unknown>;
}

export interface SimulateResult {
  run_id: number;
  status: string;
  risk_score: number;
  risk_level: string;
  diff_text: string;
  diff_added: number;
  diff_removed: number;
  affected_areas: string[];
  post_config: string;
  risk_detail: Record<string, unknown>;
}

const KEYS = {
  envs: ['lab', 'environments'] as const,
  env: (id: number) => ['lab', 'environment', id] as const,
  devices: (envId: number) => ['lab', 'environment', envId, 'devices'] as const,
  device: (id: number) => ['lab', 'device', id] as const,
  runs: (deviceId: number) => ['lab', 'device', deviceId, 'runs'] as const,
  run: (id: number) => ['lab', 'run', id] as const,
  runtime: ['lab', 'runtime'] as const,
  runtimeEvents: (deviceId: number) => ['lab', 'device', deviceId, 'runtime', 'events'] as const,
};

// ── Environments ────────────────────────────────────────────────────────────

export function useEnvironments() {
  return useQuery({
    queryKey: KEYS.envs,
    queryFn: () => apiRequest<LabEnvironment[]>('/lab/environments'),
  });
}

export function useEnvironment(envId: number | null) {
  return useQuery({
    queryKey: envId ? KEYS.env(envId) : ['lab', 'environment', 'none'],
    queryFn: () =>
      apiRequest<LabEnvironment & { devices: LabDeviceSummary[] }>(
        `/lab/environments/${envId}`,
      ),
    enabled: envId !== null && envId !== undefined,
  });
}

export function useCreateEnvironment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { name: string; description?: string; shared?: boolean }) =>
      apiRequest<{ id: number }>('/lab/environments', {
        method: 'POST',
        body,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEYS.envs }),
  });
}

export function useDeleteEnvironment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (envId: number) =>
      apiRequest<{ ok: true }>(`/lab/environments/${envId}`, {
        method: 'DELETE',
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEYS.envs }),
  });
}

// ── Devices ─────────────────────────────────────────────────────────────────

export function useDevice(deviceId: number | null) {
  return useQuery({
    queryKey: deviceId ? KEYS.device(deviceId) : ['lab', 'device', 'none'],
    queryFn: () => apiRequest<LabDevice>(`/lab/devices/${deviceId}`),
    enabled: deviceId !== null && deviceId !== undefined,
  });
}

export function useCreateDevice(envId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: {
      hostname: string;
      ip_address?: string;
      device_type?: string;
      model?: string;
      running_config?: string;
      notes?: string;
    }) =>
      apiRequest<{ id: number }>(`/lab/environments/${envId}/devices`, {
        method: 'POST',
        body,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEYS.env(envId) }),
  });
}

export function useCloneHost(envId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { host_id: number; hostname_override?: string }) =>
      apiRequest<{ id: number; config_bytes: number; snapshot_id: number | null }>(
        `/lab/environments/${envId}/clone-host`,
        { method: 'POST', body },
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEYS.env(envId) }),
  });
}

export function useDeleteDevice(envId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (deviceId: number) =>
      apiRequest<{ ok: true }>(`/lab/devices/${deviceId}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEYS.env(envId) }),
  });
}

// ── Simulate / runs ─────────────────────────────────────────────────────────

export function useSimulate(deviceId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: {
      proposed_commands?: string[];
      template_id?: number;
      apply_to_device?: boolean;
    }) =>
      apiRequest<SimulateResult>(`/lab/devices/${deviceId}/simulate`, {
        method: 'POST',
        body,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: KEYS.runs(deviceId) });
      qc.invalidateQueries({ queryKey: KEYS.device(deviceId) });
    },
  });
}

export function useRuns(deviceId: number | null) {
  return useQuery({
    queryKey: deviceId ? KEYS.runs(deviceId) : ['lab', 'runs', 'none'],
    queryFn: () => apiRequest<LabRunSummary[]>(`/lab/devices/${deviceId}/runs`),
    enabled: deviceId !== null && deviceId !== undefined,
  });
}

export function useRun(runId: number | null) {
  return useQuery({
    queryKey: runId ? KEYS.run(runId) : ['lab', 'run', 'none'],
    queryFn: () => apiRequest<LabRunDetail>(`/lab/runs/${runId}`),
    enabled: runId !== null && runId !== undefined,
  });
}

export function usePromoteRun() {
  return useMutation({
    mutationFn: ({
      runId,
      body,
    }: {
      runId: number;
      body: {
        name: string;
        description?: string;
        credential_id: number;
        target_host_ids?: number[];
        target_group_id?: number;
      };
    }) =>
      apiRequest<{ ok: true; deployment_id: number }>(
        `/lab/runs/${runId}/promote`,
        { method: 'POST', body },
      ),
  });
}

// ── Runtime (Phase B-1) ─────────────────────────────────────────────────────

export function useRuntimeStatus() {
  return useQuery({
    queryKey: KEYS.runtime,
    queryFn: () => apiRequest<LabRuntimeStatus>('/lab/runtime'),
    staleTime: 60_000,
  });
}

export function useRuntimeEvents(deviceId: number | null) {
  return useQuery({
    queryKey: deviceId ? KEYS.runtimeEvents(deviceId) : ['lab', 'runtime-events', 'none'],
    queryFn: () =>
      apiRequest<LabRuntimeEvent[]>(`/lab/devices/${deviceId}/runtime/events`),
    enabled: deviceId !== null && deviceId !== undefined,
  });
}

export function useDeployRuntime(deviceId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: {
      node_kind: string;
      image: string;
      credential_id?: number | null;
    }) =>
      apiRequest<DeployRuntimeResult>(`/lab/devices/${deviceId}/runtime/deploy`, {
        method: 'POST',
        body,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: KEYS.device(deviceId) });
      qc.invalidateQueries({ queryKey: KEYS.runtimeEvents(deviceId) });
    },
  });
}

export function useDestroyRuntime(deviceId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiRequest<{ status: string }>(`/lab/devices/${deviceId}/runtime/destroy`, {
        method: 'POST',
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: KEYS.device(deviceId) });
      qc.invalidateQueries({ queryKey: KEYS.runtimeEvents(deviceId) });
    },
  });
}

export function useRefreshRuntime(deviceId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiRequest<{ status: string; mgmt_ipv4?: string }>(
        `/lab/devices/${deviceId}/runtime/refresh`,
        { method: 'POST' },
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: KEYS.device(deviceId) });
      qc.invalidateQueries({ queryKey: KEYS.runtimeEvents(deviceId) });
    },
  });
}

export function useSimulateLive(deviceId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { proposed_commands?: string[]; template_id?: number }) =>
      apiRequest<SimulateLiveResult>(
        `/lab/devices/${deviceId}/simulate-live`,
        { method: 'POST', body },
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: KEYS.runs(deviceId) });
      qc.invalidateQueries({ queryKey: KEYS.device(deviceId) });
      qc.invalidateQueries({ queryKey: KEYS.runtimeEvents(deviceId) });
    },
  });
}
