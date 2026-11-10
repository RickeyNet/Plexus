import type { SlaStatus } from '@/api/monitoring';
import type { Tone } from '@/lib/severity';

/**
 * Tone of a "how many are bad" stat tile: `tone` while the count is above
 * zero, none at zero or while it is unknown, so a healthy 0 is not red.
 */
export function countTone(count: number | null | undefined, tone: Tone): Tone | undefined {
  return typeof count === 'number' && count > 0 ? tone : undefined;
}

// Tables of both Availability sections (polled hosts and integrations) share
// one look: DataTable, sticky header, this height cap.
export const AVAILABILITY_TABLE_MAX_HEIGHT = 520;

// Opacity of the text of a disabled rule or an inactive suppression. Applied to
// the description only, never to the row's action buttons.
export const INACTIVE_OPACITY = 0.55;

/** Uptime percentage with two decimals, or "-" when unknown. */
export function formatUptimePct(pct: number | null | undefined): string {
  return pct != null ? `${pct.toFixed(2)}%` : '-';
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
