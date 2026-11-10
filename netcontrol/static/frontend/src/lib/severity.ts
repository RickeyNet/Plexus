// One source of truth for how severities and statuses are coloured.
//
// A tone is a semantic colour, rendered through the theme tokens
// (--success, --warning, --danger, --info, --primary, --text-muted for
// neutral) by the Badge, StatTile and Callout components. Pages map a raw
// backend value to a tone here instead of keeping their own colour table.

export type Tone = 'success' | 'warning' | 'danger' | 'info' | 'neutral' | 'primary';

/** The CSS custom property that carries a tone's colour, for inline text or icon colour. */
export function toneColor(tone: Tone): string {
  return tone === 'neutral' ? 'var(--text-muted)' : `var(--${tone})`;
}

// Lower-cased, trimmed, with '_' and spaces folded to '-', so "In Progress",
// "in_progress" and "in-progress" are one key.
function normalize(value: string | null | undefined): string {
  return (value ?? '').trim().toLowerCase().replace(/[\s_]+/g, '-');
}

// ── Severity ────────────────────────────────────────────────────────────────

/** The five canonical severity levels, most severe first. */
export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const SEVERITY_LEVELS: readonly SeverityLevel[] = ['critical', 'high', 'medium', 'low', 'info'];

// Every severity vocabulary the backend uses folded onto the five levels:
// advisory/audit/compliance (critical..info), monitoring alerts
// (critical/warning/info) and syslog (emergency..debug).
const SEVERITY_ALIASES: Record<string, SeverityLevel> = {
  critical: 'critical',
  crit: 'critical',
  emergency: 'critical',
  emerg: 'critical',
  alert: 'critical',
  high: 'high',
  error: 'high',
  err: 'high',
  medium: 'medium',
  moderate: 'medium',
  warning: 'medium',
  warn: 'medium',
  low: 'low',
  notice: 'low',
  info: 'info',
  informational: 'info',
  debug: 'info',
  none: 'info',
};

/** The canonical level of a raw severity; null when it is missing or unknown. */
export function normalizeSeverity(severity: string | null | undefined): SeverityLevel | null {
  return SEVERITY_ALIASES[normalize(severity)] ?? null;
}

const SEVERITY_TONE: Record<SeverityLevel, Tone> = {
  critical: 'danger',
  high: 'danger',
  medium: 'warning',
  low: 'info',
  info: 'neutral',
};

/**
 * Tone of a severity: critical and high are danger, medium (and "warning") is
 * warning, low is info, info/none/unknown is neutral. Critical is told apart
 * from high by the solid badge (see isCriticalSeverity).
 */
export function severityTone(severity: string | null | undefined): Tone {
  const level = normalizeSeverity(severity);
  return level ? SEVERITY_TONE[level] : 'neutral';
}

/** True for critical-level severities, which render as a solid badge. */
export function isCriticalSeverity(severity: string | null | undefined): boolean {
  return normalizeSeverity(severity) === 'critical';
}

/** Sort key: 0 for critical through 4 for info; unknown severities sort last (5). */
export function severityRank(severity: string | null | undefined): number {
  const level = normalizeSeverity(severity);
  return level ? SEVERITY_LEVELS.indexOf(level) : SEVERITY_LEVELS.length;
}

// ── Compliance scan status ─────────────────────────────────────────────────

const COMPLIANCE_TONE: Record<string, Tone> = {
  compliant: 'success',
  pass: 'success',
  passed: 'success',
  'non-compliant': 'danger',
  noncompliant: 'danger',
  fail: 'danger',
  failed: 'danger',
  violation: 'danger',
  violations: 'danger',
  // The scan could not run: a problem with the scan, not a finding.
  error: 'warning',
};

/**
 * Tone of a compliance scan result: compliant/pass is success,
 * non-compliant/fail/violation is danger, error (scan could not run) is
 * warning, anything else (pending, skipped, unknown) is neutral.
 */
export function complianceStatusTone(status: string | null | undefined): Tone {
  return COMPLIANCE_TONE[normalize(status)] ?? 'neutral';
}

// ── Job / run / sync status ────────────────────────────────────────────────

const STATUS_TONE: Record<string, Tone> = {
  success: 'success',
  succeeded: 'success',
  successful: 'success',
  completed: 'success',
  complete: 'success',
  done: 'success',
  ok: 'success',
  passed: 'success',
  verified: 'success',
  approved: 'success',
  synced: 'success',
  up: 'success',
  online: 'success',

  failed: 'danger',
  failure: 'danger',
  rejected: 'danger',
  error: 'danger',
  errored: 'danger',
  'verification-failed': 'danger',
  'timed-out': 'danger',
  timeout: 'danger',
  down: 'danger',
  offline: 'danger',
  unreachable: 'danger',

  partial: 'warning',
  warning: 'warning',
  degraded: 'warning',
  'rolled-back': 'warning',

  running: 'info',
  'in-progress': 'info',
  executing: 'info',
  started: 'info',
  active: 'info',
  verifying: 'info',
  'pre-check': 'info',
  'post-check': 'info',
  'rolling-back': 'info',

  pending: 'neutral',
  queued: 'neutral',
  scheduled: 'neutral',
  waiting: 'neutral',
  planning: 'neutral',
  cancelled: 'neutral',
  canceled: 'neutral',
  skipped: 'neutral',
  never: 'neutral',
  'admin-down': 'neutral',
  unknown: 'neutral',
};

/**
 * Tone of a job, run, deployment, sync or link status: finished well is
 * success, failed is danger, partial/rolled back is warning, in progress is
 * info, and waiting/cancelled/unknown is neutral.
 */
export function statusTone(status: string | null | undefined): Tone {
  return STATUS_TONE[normalize(status)] ?? 'neutral';
}

/** True for statuses that mean work is happening now (the badge shows a live dot). */
export function isActiveStatus(status: string | null | undefined): boolean {
  return statusTone(status) === 'info';
}
