/** Pin/chip color for a host's status. Matches the legacy floor-plan module. */
export function statusColor(status: string | null | undefined): string {
  if (status === 'up' || status === 'online') return '#4caf50';
  if (status === 'down' || status === 'offline') return '#f44336';
  return '#9e9e9e';
}
