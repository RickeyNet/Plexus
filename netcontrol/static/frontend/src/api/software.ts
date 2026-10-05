/**
 * Software version tracker API - the versions every tracked device runs,
 * their spread per platform, the advisories they are checked against, the
 * resulting alerts, and the Cisco PSIRT sync.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

// ── Types ──────────────────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface SoftwareDevice {
  id: number;
  /** `host:<id>` for an inventory host, `<provider>:<org_ref>:<serial>` for a topology device. */
  device_key: string;
  source: 'inventory' | 'meraki' | 'cato' | 'anyconnect' | string;
  org_ref: number;
  host_id: number | null;
  name: string;
  model: string;
  serial: string;
  /** Inventory group, Meraki network, Cato site or AnyConnect headend. */
  site: string;
  org_name: string;
  platform: string;
  platform_label?: string;
  version: string;
  raw_version: string;
  previous_version: string;
  changed_at: string;
  first_seen: string;
  last_seen: string;
  behind_newest?: boolean;
  alert_count?: number;
  unacknowledged_alerts?: number;
  worst_severity?: string;
}

export interface SoftwareVersionCount {
  version: string;
  count: number;
  behind_newest: boolean;
}

export interface SoftwarePlatformSpread {
  platform: string;
  label: string;
  device_count: number;
  version_count: number;
  newest_version: string;
  most_common_version: string;
  behind_newest: number;
  versions: SoftwareVersionCount[];
}

export interface SoftwareAdvisory {
  id?: number;
  advisory_id: string;
  source: 'manual' | 'import' | 'cisco-psirt' | string;
  title: string;
  severity: Severity | string;
  cvss: number | null;
  /** '' = every platform. */
  platform: string;
  /** Case-insensitive substring of the model; '' = every model. */
  product_match: string;
  affected_versions: string[];
  fixed_versions: string[];
  cves: string[];
  url: string;
  published: string;
  summary: string;
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface SoftwareAdvisoryPayload {
  advisory_id: string;
  title?: string;
  severity?: string;
  cvss?: number | null;
  platform?: string;
  product_match?: string;
  affected_versions: string[];
  fixed_versions?: string[];
  cves?: string[];
  url?: string;
  published?: string;
  summary?: string;
  enabled?: boolean;
}

export interface SoftwareAlert {
  id: number;
  device_key: string;
  advisory_id: string;
  severity: Severity | string;
  first_seen: string;
  last_seen: string;
  acknowledged_at: string;
  acknowledged_by: string;
  resolved_at: string;
  acknowledged: boolean;
  resolved: boolean;
  title: string;
  url: string;
  cvss: number | null;
  advisory_source: string;
  fixed_versions: string[];
  cves: string[];
  device_name: string | null;
  model: string | null;
  version: string | null;
  platform: string | null;
  site: string | null;
  org_name: string | null;
  device_source: string | null;
  host_id: number | null;
}

export interface SoftwareVersionChange {
  device_key: string;
  name: string;
  platform: string;
  model: string;
  site: string;
  source: string;
  previous_version: string;
  version: string;
  changed_at: string;
}

export interface SoftwareSettings {
  refresh_interval_seconds: number;
  notify_enabled: boolean;
  notify_min_severity: Severity | string;
  psirt_enabled: boolean;
  psirt_client_id: string;
  has_psirt_secret: boolean;
  psirt_interval_seconds: number;
  psirt_last_sync_at: string;
  psirt_last_sync_status: string;
  psirt_last_sync_message: string;
  psirt_platforms: string[];
  last_refresh_at: string;
}

export interface SoftwareSettingsPayload {
  refresh_interval_seconds?: number;
  notify_enabled?: boolean;
  notify_min_severity?: string;
  psirt_enabled?: boolean;
  psirt_client_id?: string;
  /** Write-only: omit to keep the stored secret, '' to clear it. */
  psirt_client_secret?: string;
  psirt_interval_seconds?: number;
}

export interface SoftwareSummary {
  devices: number;
  platforms: number;
  versions: number;
  behind_newest: number;
  open_alerts: number;
  unacknowledged_alerts: number;
  /** Open alerts of severity critical or high. */
  critical_alerts: number;
  alerts_by_severity: Record<string, number>;
  advisories: number;
  enabled_advisories: number;
  sources: Record<string, number>;
  last_refresh_at: string;
}

export interface SoftwarePlatformInfo {
  key: string;
  label: string;
  /** Cisco PSIRT can be asked about this platform's versions. */
  psirt: boolean;
}

export interface SoftwareOverview {
  summary: SoftwareSummary;
  platforms: SoftwarePlatformSpread[];
  platform_catalog: SoftwarePlatformInfo[];
  severities: string[];
  devices: SoftwareDevice[];
  alerts: SoftwareAlert[];
  advisories: SoftwareAdvisory[];
  changes: SoftwareVersionChange[];
  settings: SoftwareSettings;
}

export interface SoftwareRefreshResult {
  devices: number;
  added: number;
  changed: number;
  removed: number;
  changes: { device_key: string; name: string; from_version: string; to_version: string }[];
  refreshed_at: string;
  alerts: { open: number; new: number; reopened: number; resolved: number; notified: number };
}

export interface SoftwareHistoryEntry {
  version: string;
  platform: string;
  seen_from: string;
  seen_until: string;
}

export interface PsirtSyncJob {
  job_id: string;
  status: 'running' | 'completed' | 'partial' | 'failed';
  progress: { phase?: string; done?: number; total?: number; current?: string };
  result: {
    versions_checked?: number;
    advisories?: number;
    errors?: string[];
    message?: string;
    alerts?: { open: number; new: number };
  } | null;
  error: string | null;
}

// ── Query keys ─────────────────────────────────────────────────────────────

export const KEYS = {
  overview: (platform: string, source: string, search: string) =>
    ['software-overview', platform, source, search] as const,
  history: (deviceKey: string) => ['software-history', deviceKey] as const,
  settings: ['software-settings'] as const,
  psirtJob: (jobId: string | null) => ['software-psirt-job', jobId] as const,
};

function invalidateAll(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: ['software-overview'] });
  qc.invalidateQueries({ queryKey: ['software-settings'] });
}

// ── Queries ────────────────────────────────────────────────────────────────

export function useSoftwareOverview(platform: string, source: string, search: string) {
  return useQuery<SoftwareOverview>({
    queryKey: KEYS.overview(platform, source, search),
    queryFn: () => {
      const params: Record<string, string> = {};
      if (platform) params.platform = platform;
      if (source) params.source = source;
      if (search.trim()) params.search = search.trim();
      const qs = new URLSearchParams(params).toString();
      return apiRequest(`/software/overview${qs ? `?${qs}` : ''}`);
    },
  });
}

export function useSoftwareHistory(deviceKey: string | null) {
  return useQuery<{ device_key: string; history: SoftwareHistoryEntry[] }>({
    queryKey: KEYS.history(deviceKey ?? ''),
    queryFn: () => apiRequest(`/software/history?device_key=${encodeURIComponent(deviceKey!)}`),
    enabled: !!deviceKey,
  });
}

export function useSoftwareSettings(enabled: boolean) {
  return useQuery<{ settings: SoftwareSettings }>({
    queryKey: KEYS.settings,
    queryFn: () => apiRequest('/software/settings'),
    enabled,
  });
}

export function usePsirtSyncJob(jobId: string | null) {
  return useQuery<PsirtSyncJob>({
    queryKey: KEYS.psirtJob(jobId),
    queryFn: () => apiRequest(`/software/psirt/jobs/${jobId}`),
    enabled: jobId != null,
    // A sync is a background job with no push channel; poll until it settles.
    refetchInterval: (query) => (query.state.data?.status === 'running' ? 2000 : false),
  });
}

// ── Mutations ──────────────────────────────────────────────────────────────

export function useRefreshSoftware() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => apiRequest<SoftwareRefreshResult>('/software/refresh', { method: 'POST' }),
    onSuccess: () => invalidateAll(qc),
  });
}

export function useSaveSoftwareAdvisory() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ payload, existing }: { payload: SoftwareAdvisoryPayload; existing: boolean }) =>
      existing
        ? apiRequest(`/software/advisories/${encodeURIComponent(payload.advisory_id)}`, {
            method: 'PUT',
            body: payload,
          })
        : apiRequest('/software/advisories', { method: 'POST', body: payload }),
    onSuccess: () => invalidateAll(qc),
  });
}

export function useDeleteSoftwareAdvisory() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (advisoryId: string) =>
      apiRequest(`/software/advisories/${encodeURIComponent(advisoryId)}`, { method: 'DELETE' }),
    onSuccess: () => invalidateAll(qc),
  });
}

export function useImportSoftwareAdvisories() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (advisories: SoftwareAdvisoryPayload[]) =>
      apiRequest<{ imported: number }>('/software/advisories/import', {
        method: 'POST',
        body: { advisories },
      }),
    onSuccess: () => invalidateAll(qc),
  });
}

export function useAcknowledgeSoftwareAlert() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (alertId: number) =>
      apiRequest(`/software/alerts/${alertId}/acknowledge`, { method: 'POST' }),
    onSuccess: () => invalidateAll(qc),
  });
}

export function useSaveSoftwareSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: SoftwareSettingsPayload) =>
      apiRequest<{ settings: SoftwareSettings }>('/software/settings', { method: 'PUT', body: payload }),
    onSuccess: () => invalidateAll(qc),
  });
}

export function useTestPsirt() {
  return useMutation({
    mutationFn: () => apiRequest<{ ok: boolean; message: string }>('/software/psirt/test', { method: 'POST' }),
  });
}

export function useStartPsirtSync() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => apiRequest<{ job_id: string }>('/software/psirt/sync', { method: 'POST' }),
    onSuccess: () => invalidateAll(qc),
  });
}
