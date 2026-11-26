/**
 * Hardware lifecycle under /api/lifecycle: end-of-life notices (on a device
 * type or a part number), support contracts with the devices they cover,
 * the lifecycle status of every device and of one, the alert check settings
 * and the check itself. Failures throw a `CustomDataError`: a 422 carries
 * per-field `fields`, a 409 a duplicate device type, part number or
 * contract id.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import type { CoverageState, LifecycleStage, LifecycleFilter } from '@/lib/lifecycle';

import { queryString } from './client';
import { detailRequest, listOf } from './customData';

// ── Types ──────────────────────────────────────────────────────────────────

interface Stamps {
  created_by: string;
  created_at: string;
  updated_at: string;
  updated_by: string;
}

export type MilestoneKey = 'end_of_sale' | 'end_of_sw_maintenance' | 'end_of_security_fixes' | 'end_of_support';
export type ContractState = 'covered' | 'expiring' | 'expired' | 'not_started';
export type NoticeVia = 'device_type' | 'part_number' | 'module';

export interface NextMilestone {
  milestone: MilestoneKey;
  label: string;
  date: string;
  days: number;
  notice_id?: number;
}

export interface HardwareNotice extends Stamps {
  id: number;
  device_type_id: number | null;
  device_type_model: string | null;
  device_type_part_number: string | null;
  manufacturer_name: string | null;
  part_number: string;
  end_of_sale: string;
  end_of_sw_maintenance: string;
  end_of_security_fixes: string;
  end_of_support: string;
  documentation_url: string;
  comments: string;
  host_count: number;
  /** Where the notice puts a device today. */
  stage: LifecycleStage;
  next: NextMilestone | null;
  /** On a device's answer only: how the notice applies to it. */
  via?: NoticeVia[];
}

export interface HostRef {
  id: number;
  hostname: string;
  ip_address: string;
}

export interface NoticeDetail extends HardwareNotice {
  hosts: (HostRef & { via: NoticeVia[] })[];
}

export interface SupportContract extends Stamps {
  id: number;
  provider: string;
  contract_id: string;
  start_date: string;
  end_date: string;
  /** Exact amount as text (two decimals), or null. */
  cost: string | null;
  currency: string;
  support_level: string;
  description: string;
  comments: string;
  host_count: number;
  hosts: HostRef[];
  state: ContractState;
}

export interface DeviceLifecycle {
  host_id: number;
  hostname: string;
  ip_address: string;
  serial_number: string;
  model: string;
  device_type_id: number | null;
  device_type_model: string | null;
  manufacturer_name: string | null;
  lifecycle_status_name: string | null;
  notice_ids: number[];
  stage: LifecycleStage;
  next: NextMilestone | null;
  end_of_sale: string | null;
  days_to_end_of_sale: number | null;
  end_of_support: string | null;
  days_to_end_of_support: number | null;
  coverage: CoverageState;
  coverage_end: string | null;
  coverage_days: number | null;
  contracts: { id: number; provider: string; contract_id: string; end_date: string; state: ContractState }[];
}

export interface LifecycleSettings {
  alerts_enabled: boolean;
  contract_warn_days: number;
  support_warn_days: number;
  last_check_at: string;
  last_check_alerts: number;
}

export interface FleetSummary {
  devices: number;
  with_notice: number;
  past_end_of_support: number;
  by_stage: Record<LifecycleStage, number>;
  by_coverage: Record<CoverageState, number>;
}

export interface FleetStatus {
  summary: FleetSummary;
  devices: DeviceLifecycle[];
  settings: LifecycleSettings;
}

export interface HostLifecycle {
  host_id: number;
  status: DeviceLifecycle;
  notices: HardwareNotice[];
  contracts: SupportContract[];
}

export interface LifecycleChoices {
  hosts: HostRef[];
  device_types: { id: number; manufacturer: string; model: string; part_number: string }[];
}

export interface NoticeInput {
  device_type_id: number | null;
  part_number: string;
  end_of_sale: string;
  end_of_sw_maintenance: string;
  end_of_security_fixes: string;
  end_of_support: string;
  documentation_url: string;
  comments: string;
}

export interface ContractInput {
  provider: string;
  contract_id: string;
  start_date: string;
  end_date: string;
  cost: string | null;
  currency: string;
  support_level: string;
  description: string;
  comments: string;
  host_ids: number[];
}

export interface CheckResult {
  ok: boolean;
  conditions: number;
  raised: number;
  cleared: number;
}

// ── Query keys ─────────────────────────────────────────────────────────────

const ROOT = ['lifecycle'] as const;
export const LIFECYCLE_KEYS = {
  status: (filter: LifecycleFilter) => [...ROOT, 'status', filter] as const,
  notices: [...ROOT, 'notices'] as const,
  notice: (id: number) => [...ROOT, 'notice', id] as const,
  contracts: [...ROOT, 'contracts'] as const,
  host: (hostId: number) => [...ROOT, 'host', hostId] as const,
  choices: [...ROOT, 'choices'] as const,
  settings: [...ROOT, 'settings'] as const,
};

// ── Queries ────────────────────────────────────────────────────────────────

export function useFleetLifecycle(filter: LifecycleFilter) {
  return useQuery<FleetStatus>({
    queryKey: LIFECYCLE_KEYS.status(filter),
    queryFn: ({ signal }) => detailRequest<FleetStatus>(`/lifecycle/status${queryString(filter)}`, { signal }),
  });
}

export function useHardwareNotices() {
  return useQuery<HardwareNotice[]>({
    queryKey: LIFECYCLE_KEYS.notices,
    queryFn: async ({ signal }) => listOf<HardwareNotice>(await detailRequest('/lifecycle/notices', { signal }), 'notices'),
  });
}

export function useHardwareNotice(id: number | null) {
  return useQuery<NoticeDetail>({
    queryKey: LIFECYCLE_KEYS.notice(id ?? 0),
    queryFn: ({ signal }) => detailRequest<NoticeDetail>(`/lifecycle/notices/${id}`, { signal }),
    enabled: id !== null,
  });
}

export function useSupportContracts() {
  return useQuery<SupportContract[]>({
    queryKey: LIFECYCLE_KEYS.contracts,
    queryFn: async ({ signal }) => listOf<SupportContract>(await detailRequest('/lifecycle/contracts', { signal }), 'contracts'),
  });
}

/** One device's lifecycle: status, the notices that apply and its contracts. */
export function useHostLifecycle(hostId: number | null, enabled = true) {
  return useQuery<HostLifecycle>({
    queryKey: LIFECYCLE_KEYS.host(hostId ?? 0),
    queryFn: ({ signal }) => detailRequest<HostLifecycle>(`/lifecycle/hosts/${hostId}`, { signal }),
    enabled: enabled && hostId !== null,
  });
}

export function useLifecycleChoices() {
  return useQuery<LifecycleChoices>({
    queryKey: LIFECYCLE_KEYS.choices,
    queryFn: ({ signal }) => detailRequest<LifecycleChoices>('/lifecycle/choices', { signal }),
  });
}

export function useLifecycleSettings() {
  return useQuery<LifecycleSettings>({
    queryKey: LIFECYCLE_KEYS.settings,
    queryFn: ({ signal }) => detailRequest<LifecycleSettings>('/lifecycle/settings', { signal }),
  });
}

// ── Mutations ──────────────────────────────────────────────────────────────

function useWrite<TBody, TResult = unknown>(request: (body: TBody) => Promise<TResult>) {
  const qc = useQueryClient();
  return useMutation<TResult, Error, TBody>({
    mutationFn: request,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ROOT });
      qc.invalidateQueries({ queryKey: ['object-changes'] });
    },
  });
}

export function useSaveNotice() {
  return useWrite<{ id: number | null; data: NoticeInput }, HardwareNotice>(({ id, data }) =>
    detailRequest<HardwareNotice>(id === null ? '/lifecycle/notices' : `/lifecycle/notices/${id}`, {
      method: id === null ? 'POST' : 'PUT',
      body: data,
    }),
  );
}

export function useDeleteNotice() {
  return useWrite<number>((id) => detailRequest(`/lifecycle/notices/${id}`, { method: 'DELETE' }));
}

export function useSaveContract() {
  return useWrite<{ id: number | null; data: ContractInput }, SupportContract>(({ id, data }) =>
    detailRequest<SupportContract>(id === null ? '/lifecycle/contracts' : `/lifecycle/contracts/${id}`, {
      method: id === null ? 'POST' : 'PUT',
      body: data,
    }),
  );
}

export function useDeleteContract() {
  return useWrite<number>((id) => detailRequest(`/lifecycle/contracts/${id}`, { method: 'DELETE' }));
}

export function useSaveLifecycleSettings() {
  return useWrite<Partial<Pick<LifecycleSettings, 'alerts_enabled' | 'contract_warn_days' | 'support_warn_days'>>, LifecycleSettings>(
    (data) => detailRequest<LifecycleSettings>('/lifecycle/settings', { method: 'PUT', body: data }),
  );
}

/** Run the lifecycle alert check now. */
export function useRunLifecycleCheck() {
  return useWrite<void, CheckResult>(() => detailRequest<CheckResult>('/lifecycle/check', { method: 'POST' }));
}

/** The device statuses as CSV (browser handles the download). */
export function lifecycleExportUrl(filter: LifecycleFilter): string {
  return `/api/lifecycle/status/export${queryString(filter)}`;
}
