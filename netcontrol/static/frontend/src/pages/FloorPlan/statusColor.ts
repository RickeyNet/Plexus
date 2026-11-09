/** Pin/chip color for a host's status. Matches the legacy floor-plan module. */
export function statusColor(status: string | null | undefined): string {
  if (status === 'up' || status === 'online') return 'var(--success)';
  if (status === 'down' || status === 'offline') return 'var(--danger)';
  return 'var(--text-muted)';
}
