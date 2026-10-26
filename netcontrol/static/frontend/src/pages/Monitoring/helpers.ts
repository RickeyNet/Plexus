import type { SlaStatus } from '@/api/monitoring';

export function formatTimestamp(ts: string | null | undefined): string {
  if (!ts) return '-';
  return new Date(ts + (ts.endsWith('Z') ? '' : 'Z')).toLocaleString();
}

export function formatUptime(seconds: number | null | undefined): string {
  if (seconds == null) return 'N/A';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

export function formatMinutes(min: number | null | undefined): string {
  if (min == null) return '-';
  if (min < 60) return `${min.toFixed(1)}m`;
  const h = Math.floor(min / 60);
  const m = Math.round(min % 60);
  return `${h}h ${m}m`;
}

export const SEVERITY_COLOR: Record<string, string> = {
  critical: 'danger',
  warning: 'warning',
  info: 'primary',
};

export function severityColor(sev: string | undefined | null): string {
  if (!sev) return 'text-muted';
  return SEVERITY_COLOR[sev] ?? 'text-muted';
}

// Badge class and label of each server-computed SLA status (see
// /api/sla/compliance); `none` is a host with no SLA target.
export const SLA_STATUS_BADGE: Record<SlaStatus | 'none', { cls: string; label: string }> = {
  met: { cls: 'badge badge-success', label: 'Met' },
  warn: { cls: 'badge badge-warning', label: 'Warning' },
  breach: { cls: 'badge badge-danger', label: 'Breach' },
  no_data: { cls: 'badge badge-secondary', label: 'No Data' },
  none: { cls: 'badge badge-secondary', label: 'No Target' },
};

export function slaStatusBadge(status: SlaStatus | null | undefined): { cls: string; label: string } {
  return SLA_STATUS_BADGE[status ?? 'none'];
}
