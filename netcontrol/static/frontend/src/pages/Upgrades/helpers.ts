export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function formatBackupTimestamp(iso: string | null | undefined): string {
  if (!iso) return '';
  // Backend emits naive local time without a Z suffix. Match the legacy
  // module's display by stripping the T and trimming sub-second precision.
  return iso.replace('T', ' ').slice(0, 19);
}

export type UpgradePhase =
  | 'prestage'
  | 'transfer'
  | 'activate'
  | 'verify'
  | 'verify_prestage';

export function phaseLabel(phase: UpgradePhase | string): string {
  const labels: Record<string, string> = {
    prestage: 'Prestage',
    transfer: 'Transfer',
    activate: 'Activate',
    verify: 'Verify Upgrade',
    verify_prestage: 'Re-Verify Prestage',
  };
  return (
    labels[phase] ||
    phase.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
  );
}

export function campaignStatusBadgeClass(
  status: string | null | undefined,
  isRunning: boolean,
): string {
  if (status?.includes('failed')) return 'badge-error';
  if (isRunning) return 'badge-info';
  if (status?.includes('complete')) return 'badge-success';
  return 'badge-secondary';
}
