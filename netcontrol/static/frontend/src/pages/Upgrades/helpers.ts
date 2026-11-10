import { formatBackendDateTime, formatRelativeTime, parseBackendDate } from '@/lib/datetime';
import type { Tone } from '@/lib/severity';

/** State of the campaign viewer's live event stream (its WebSocket). */
export type LiveStreamState = 'connecting' | 'open' | 'closed' | 'error';

// What the operator is told about the live stream, instead of the raw
// socket state: a badge label and tone, whether it pulses, and a hint.
export function liveStreamStatus(state: LiveStreamState): {
  label: string;
  tone: Tone;
  live: boolean;
  title: string;
} {
  switch (state) {
    case 'open':
      return { label: 'Live', tone: 'success', live: true, title: 'Events appear here as they happen' };
    case 'connecting':
      return { label: 'Connecting…', tone: 'info', live: false, title: 'Opening the live event stream' };
    case 'error':
      return {
        label: 'Not connected',
        tone: 'danger',
        live: false,
        title: 'The live event stream could not be opened. Close and reopen the campaign to retry.',
      };
    default:
      return {
        label: 'Disconnected',
        tone: 'neutral',
        live: false,
        title: 'The live event stream closed. Close and reopen the campaign to reconnect.',
      };
  }
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

// Boot mode badge for the campaign table: INSTALL (upgradable), BUNDLE
// (install-mode upgrades and ISSU are blocked until converted), or unread.
export function bootModeDisplay(mode: string | null | undefined): {
  label: string;
  badgeClass: string;
  title: string;
} {
  if (mode === 'install') {
    return {
      label: 'INSTALL',
      badgeClass: 'badge-success',
      title: 'Install mode: install-mode upgrades and ISSU can run',
    };
  }
  if (mode === 'bundle') {
    return {
      label: 'BUNDLE',
      badgeClass: 'badge-danger',
      title:
        'Bundle mode: install-mode upgrades and ISSU are blocked. Convert the switch to install mode (boot flash:packages.conf) first.',
    };
  }
  return {
    label: '-',
    badgeClass: '',
    title: 'Not read yet: Prestage, Transfer or Check status reads it from the switch',
  };
}

// scp-style clock for transfer ETA/elapsed: "00:54", "12:07", "1:02:33".
// Unknown (null/negative/non-finite) renders as scp's "--:--".
export function formatEta(seconds: number | null | undefined): string {
  if (seconds == null || !Number.isFinite(seconds) || seconds < 0) return '--:--';
  const s = Math.floor(seconds);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const pad = (n: number) => String(n).padStart(2, '0');
  return h ? `${h}:${pad(m)}:${pad(sec)}` : `${pad(m)}:${pad(sec)}`;
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
    // Phase key kept for stored history; it is the read-only status check.
    verify_prestage: 'Check Status',
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
  if (status?.includes('failed')) return 'badge-danger';
  // Pending or missed schedules take precedence over the running flag: a
  // scheduled campaign keeps an armed (sleeping) task, so isRunning is true,
  // but we want it to read as "waiting", not "in progress".
  if (status === 'activate_missed') return 'badge-warning';
  if (status?.startsWith('scheduled_')) return 'badge-warning';
  if (isRunning) return 'badge-info';
  if (status?.includes('complete')) return 'badge-success';
  return 'badge-secondary';
}

// Human-friendly version of the raw campaign status strings the backend
// stores (e.g. "scheduled_activate", "running_transfer", "activate_missed").
// Showing the raw token to operators is confusing, so translate the common
// ones and fall back to a generic prettifier for anything new.
const STATUS_LABELS: Record<string, string> = {
  created: 'Created',
  scheduled_activate: 'Reload scheduled',
  running_prestage: 'Prestaging…',
  running_transfer: 'Transferring…',
  running_activate: 'Activating (reload)…',
  running_verify: 'Verifying…',
  running_verify_prestage: 'Checking status…',
  prestage_complete: 'Prestage complete',
  transfer_complete: 'Transfer complete',
  activate_complete: 'Activated',
  verify_complete: 'Verified',
  verify_prestage_complete: 'Status checked — all ready',
  verify_prestage_partial: 'Status checked',
  verify_prestage_failed: 'Status checked — none ready',
  activate_missed: 'Reload missed — reschedule',
  cancelled: 'Cancelled',
};

export function campaignStatusLabel(
  status: string | null | undefined,
): string {
  if (!status) return 'Created';
  const mapped = STATUS_LABELS[status];
  if (mapped) return mapped;
  if (status.endsWith('_failed')) {
    return `${phaseLabel(status.slice(0, -'_failed'.length))} failed`;
  }
  if (status.endsWith('_complete')) {
    return `${phaseLabel(status.slice(0, -'_complete'.length))} complete`;
  }
  if (status.startsWith('running_')) {
    return `${phaseLabel(status.slice('running_'.length))}…`;
  }
  if (status.startsWith('scheduled_')) {
    return `${phaseLabel(status.slice('scheduled_'.length))} scheduled`;
  }
  return status.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

// Parse a stored scheduled_at (ISO 8601, UTC offset) and render it in the
// viewer's local timezone plus a relative span. Returns null for missing or
// unparseable input so callers can simply skip rendering.
export function formatScheduledTime(
  iso: string | null | undefined,
  now: number = Date.now(),
): { absolute: string; relative: string } | null {
  const when = parseBackendDate(iso);
  if (!when) return null;
  return { absolute: formatBackendDateTime(when), relative: formatRelativeTime(when, now) };
}

