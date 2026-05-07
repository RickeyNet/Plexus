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
