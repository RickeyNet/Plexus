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
