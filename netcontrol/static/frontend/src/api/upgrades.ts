import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

export interface ConfigBackup {
  filename: string;
  size: number;
  modified: string | null;
}

export function useUpgradeBackups() {
  return useQuery({
    queryKey: ['upgrade-backups'],
    queryFn: () => apiRequest<ConfigBackup[]>('/upgrades/backups'),
  });
}

export function useDeleteUpgradeBackup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (filename: string) =>
      apiRequest<{ ok: boolean }>(
        `/upgrades/backups/${encodeURIComponent(filename)}`,
        { method: 'DELETE' },
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['upgrade-backups'] });
    },
  });
}

// Backup downloads stream a file response, so consumers should navigate
// directly to this URL rather than fetching it through apiRequest. The
// browser will follow the session cookie and let the user save the file.
export function upgradeBackupDownloadUrl(filename: string): string {
  return `/api/upgrades/backups/${encodeURIComponent(filename)}`;
}

export interface UpgradeImage {
  id: number;
  filename: string;
  original_name?: string | null;
  file_size: number;
  md5_hash: string;
  model_pattern: string;
  version: string;
  platform: string;
  notes: string;
  uploaded_by?: string | null;
  created_at?: string | null;
}

export interface UpgradeImageUpdate {
  model_pattern?: string;
  version?: string;
  platform?: string;
  notes?: string;
}

export interface UploadImageResult {
  id: number;
  filename: string;
  file_size: number;
  md5_hash: string;
  version: string;
  model_pattern: string;
}

export function useUpgradeImages() {
  return useQuery({
    queryKey: ['upgrade-images'],
    queryFn: () => apiRequest<UpgradeImage[]>('/upgrades/images'),
  });
}

export function useUploadUpgradeImage() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (file: File) => {
      const fd = new FormData();
      fd.append('file', file);
      return apiRequest<UploadImageResult>('/upgrades/images', {
        method: 'POST',
        body: fd,
      });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['upgrade-images'] });
    },
  });
}

export function useUpdateUpgradeImage() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: number; body: UpgradeImageUpdate }) =>
      apiRequest<{ ok: boolean }>(`/upgrades/images/${id}`, {
        method: 'PATCH',
        body,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['upgrade-images'] });
    },
  });
}

export function useDeleteUpgradeImage() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest<{ ok: boolean }>(`/upgrades/images/${id}`, {
        method: 'DELETE',
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['upgrade-images'] });
    },
  });
}

// ── Campaigns ──────────────────────────────────────────────────────────────

export type UpgradePhase =
  | 'prestage'
  | 'transfer'
  | 'activate'
  | 'verify'
  | 'verify_prestage';

export interface UpgradeCampaignSummary {
  id: number;
  name: string;
  description: string;
  status: string;
  device_count: number;
  devices_completed: number;
  devices_failed: number;
  is_actively_running: boolean;
  created_at?: string | null;
  created_by?: string | null;
  scheduled_at?: string | null;
}

export interface UpgradeDevice {
  id: number;
  campaign_id: number;
  host_id: number | null;
  ip_address: string;
  hostname?: string | null;
  model?: string | null;
  current_version?: string | null;
  target_image?: string | null;
  phase?: string | null;
  prestage_status?: string | null;
  transfer_status?: string | null;
  activate_status?: string | null;
  verify_status?: string | null;
  error_message?: string | null;
}

export interface UpgradeCampaign extends UpgradeCampaignSummary {
  image_map: Record<string, string> | string;
  options: Record<string, unknown> | string;
  devices: UpgradeDevice[];
}

export interface UpgradeCampaignOptions {
  skip_backup?: boolean;
  skip_md5?: boolean;
  skip_health_check?: boolean;
  verify_upgrade?: boolean;
  parallel?: number;
  retries?: number;
}

export interface UpgradeCampaignInput {
  name: string;
  description: string;
  image_map: Record<string, string>;
  credential_id: number;
  host_ids: number[];
  ad_hoc_ips: string[];
  options: UpgradeCampaignOptions;
}

export interface ExecutePhasePayload {
  phase: UpgradePhase;
  device_ids?: number[];
  scheduled_at?: string | null;
}

export function useUpgradeCampaigns() {
  return useQuery({
    queryKey: ['upgrade-campaigns'],
    queryFn: () => apiRequest<UpgradeCampaignSummary[]>('/upgrades/campaigns'),
  });
}

export function useUpgradeCampaign(id: number | null) {
  return useQuery({
    queryKey: ['upgrade-campaign', id],
    queryFn: () => apiRequest<UpgradeCampaign>(`/upgrades/campaigns/${id}`),
    enabled: id !== null,
  });
}

export function useCreateUpgradeCampaign() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: UpgradeCampaignInput) =>
      apiRequest<{ id: number; devices_added: number }>('/upgrades/campaigns', {
        method: 'POST',
        body,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['upgrade-campaigns'] });
    },
  });
}

export function useUpdateUpgradeCampaign() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: number; body: UpgradeCampaignInput }) =>
      apiRequest<{ ok: boolean; total_devices: number; devices_added: number }>(
        `/upgrades/campaigns/${id}`,
        { method: 'PATCH', body },
      ),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: ['upgrade-campaigns'] });
      qc.invalidateQueries({ queryKey: ['upgrade-campaign', vars.id] });
    },
  });
}

export function useDeleteUpgradeCampaign() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest<{ ok: boolean }>(`/upgrades/campaigns/${id}`, {
        method: 'DELETE',
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['upgrade-campaigns'] });
    },
  });
}

export function useExecuteUpgradePhase() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      campaignId,
      payload,
    }: {
      campaignId: number;
      payload: ExecutePhasePayload;
    }) =>
      apiRequest<{
        ok: boolean;
        phase: string;
        device_count: number;
        scheduled: boolean;
        scheduled_at: string | null;
      }>(`/upgrades/campaigns/${campaignId}/execute`, {
        method: 'POST',
        body: payload,
      }),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: ['upgrade-campaigns'] });
      qc.invalidateQueries({
        queryKey: ['upgrade-campaign', vars.campaignId],
      });
    },
  });
}

export function useCancelUpgradeCampaign() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (campaignId: number) =>
      apiRequest<{ ok: boolean }>(
        `/upgrades/campaigns/${campaignId}/cancel`,
        { method: 'POST' },
      ),
    onSuccess: (_data, campaignId) => {
      qc.invalidateQueries({ queryKey: ['upgrade-campaigns'] });
      qc.invalidateQueries({ queryKey: ['upgrade-campaign', campaignId] });
    },
  });
}

export interface UpgradeEvent {
  id: number;
  campaign_id: number;
  device_id: number | null;
  level: string;
  message: string;
  host?: string;
  timestamp: string;
}

export function useUpgradeDeviceEvents(
  campaignId: number | null,
  deviceId: number | null,
) {
  return useQuery({
    queryKey: ['upgrade-events', campaignId, deviceId],
    queryFn: () =>
      apiRequest<UpgradeEvent[]>(
        `/upgrades/campaigns/${campaignId}/events?device_id=${deviceId}`,
      ),
    enabled: campaignId !== null && deviceId !== null,
  });
}
