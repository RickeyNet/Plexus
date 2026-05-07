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
