/**
 * Remediation of intended configuration: the commands that close a host's
 * gap to its intended configuration (`/api/intended-config/.../remediation`),
 * the admin's ignore rules, and deployments planned from the commands
 * (`/api/deployments/intended-remediation`), which then go through the usual
 * approval, execute and rollback flow. Failures throw a `CustomDataError`.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import type { ReadOptions } from './client';
import { detailRequest, listOf } from './customData';
import { INTENDED_CONFIG_QUERY_ROOT } from './intendedConfig';

/** `ok`: `commands` (empty when the device matches); `unsupported`: its driver; `unavailable`: nothing to compare. */
export type RemediationState = 'ok' | 'unsupported' | 'unavailable';

export interface HostRemediation {
  host_id: number;
  hostname: string;
  ip_address: string;
  device_type: string;
  group_id: number | null;
  template_name: string;
  backup: { id: number; captured_at: string } | null;
  state: RemediationState | string;
  /** Why there are no commands, when `state` is not `ok`. */
  reason: string;
  supported: boolean;
  platform: string;
  commands: string[];
  added: number;
  removed: number;
  /** Lines the ignore rules dropped, on both sides. */
  ignored: number;
  notes: string[];
}

/** Exactly one of the three. */
export interface RemediationTargets {
  host_ids?: number[];
  group_id?: number;
  dynamic_group_id?: number;
}

export interface RemediationDeploymentRequest extends RemediationTargets {
  credential_id: number;
  name?: string;
  description?: string;
}

export interface RemediationDeploymentResult {
  deployments: {
    id: number;
    host_id: number;
    hostname: string;
    status: string;
    requires_approval: boolean;
    approval_status: string;
    commands: number;
  }[];
  skipped: { host_id: number; hostname: string; reason: string }[];
}

export type IgnoreKind = 'exact' | 'prefix' | 'regex';

export interface IgnoreRuleInput {
  kind: IgnoreKind;
  pattern: string;
  /** Driver key, `''` for every driver. */
  device_type: string;
  description: string;
  enabled: boolean;
}

export interface IgnoreRule extends IgnoreRuleInput {
  id: number;
  created_at: string;
  updated_at: string;
  updated_by: string;
}

const BASE = '/intended-config';

/** One call per route; exported so tests can check the method, URL and body. */
export const remediationApi = {
  host: (hostId: number, opts?: ReadOptions) => detailRequest<HostRemediation>(`${BASE}/hosts/${hostId}/remediation`, opts),
  ignores: async (opts?: ReadOptions) => listOf<IgnoreRule>(await detailRequest(`${BASE}/remediation-ignores`, opts), 'rules'),
  createIgnore: (data: IgnoreRuleInput) => detailRequest<IgnoreRule>(`${BASE}/remediation-ignores`, { method: 'POST', body: data }),
  updateIgnore: (id: number, data: IgnoreRuleInput) =>
    detailRequest<IgnoreRule>(`${BASE}/remediation-ignores/${id}`, { method: 'PUT', body: data }),
  deleteIgnore: (id: number) => detailRequest<{ ok: boolean }>(`${BASE}/remediation-ignores/${id}`, { method: 'DELETE' }),
  createDeployments: (body: RemediationDeploymentRequest) =>
    detailRequest<RemediationDeploymentResult>('/deployments/intended-remediation', { method: 'POST', body }),
};

// Under the intended-config root, so regenerating or a template change refetches them.
export const REMEDIATION_KEYS = {
  host: (hostId: number) => [...INTENDED_CONFIG_QUERY_ROOT, 'remediation', hostId] as const,
  ignores: [...INTENDED_CONFIG_QUERY_ROOT, 'remediation-ignores'] as const,
};

/** The host's remediation commands; fetched only while `hostId` is set. */
export function useHostRemediation(hostId: number | null) {
  return useQuery<HostRemediation>({
    queryKey: REMEDIATION_KEYS.host(hostId ?? 0),
    queryFn: ({ signal }) => remediationApi.host(hostId!, { signal }),
    enabled: hostId !== null,
  });
}

/** Admin only. */
export function useRemediationIgnores(enabled = true) {
  return useQuery<IgnoreRule[]>({ queryKey: REMEDIATION_KEYS.ignores, queryFn: ({ signal }) => remediationApi.ignores({ signal }), enabled });
}

type QC = ReturnType<typeof useQueryClient>;

/** A rule change alters every host's commands. */
function invalidateIntended(qc: QC) {
  qc.invalidateQueries({ queryKey: INTENDED_CONFIG_QUERY_ROOT });
}

export function useCreateRemediationIgnore() {
  const qc = useQueryClient();
  return useMutation<IgnoreRule, Error, IgnoreRuleInput>({
    mutationFn: remediationApi.createIgnore,
    onSuccess: () => invalidateIntended(qc),
  });
}

export function useUpdateRemediationIgnore() {
  const qc = useQueryClient();
  return useMutation<IgnoreRule, Error, { id: number; data: IgnoreRuleInput }>({
    mutationFn: ({ id, data }) => remediationApi.updateIgnore(id, data),
    onSuccess: () => invalidateIntended(qc),
  });
}

export function useDeleteRemediationIgnore() {
  const qc = useQueryClient();
  return useMutation<unknown, Error, number>({
    mutationFn: remediationApi.deleteIgnore,
    onSuccess: () => invalidateIntended(qc),
  });
}

/** Plans one deployment per host; the Deployments list refetches. */
export function useCreateRemediationDeployments() {
  const qc = useQueryClient();
  return useMutation<RemediationDeploymentResult, Error, RemediationDeploymentRequest>({
    mutationFn: remediationApi.createDeployments,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['deployments'] });
      qc.invalidateQueries({ queryKey: ['deployment-summary'] });
    },
  });
}
