/**
 * Shared by the alert feed panels (Meraki alerts, the vendor alert feeds such
 * as the Cato events feed): one row shape for the table, the labels of how
 * Plexus alerted, the poll status of a feed and the Poll Now summary.
 */
import type { MerakiAlert } from '@/api/merakiAlerts';
import type { VendorAlert } from '@/api/vendorAlerts';

export interface AlertFeedRow {
  key: string;
  severity: string;
  status: 'open' | 'resolved';
  title: string;
  message: string;
  /** The device, site or link the alert is about. */
  subject: string;
  /** Where it is (network, site). */
  where: string;
  /** The source (organization, account). */
  source: string;
  startedAt: string;
  /** The last event, or when it resolved. */
  lastAt: string;
  /** How the vendor reported it (``poll, webhook``; the event sub-type). */
  via: string;
  alertVia: string;
  muted: boolean;
}

export const ALERT_VIA_LABELS: Record<string, string> = {
  monitoring: 'Host alert',
  notification: 'Notified',
  topology: 'Already notified (availability)',
  muted: 'Muted',
};

/** What Plexus did with an alert, for the table's last column. */
export function alertViaText(alertVia: string, severity: string): string {
  return ALERT_VIA_LABELS[alertVia] ?? (severity === 'info' ? 'Listed only' : '-');
}

export const FEED_STATUS_LABELS: Record<string, string> = {
  ok: 'Reading',
  positioned: 'Started (reads from now on)',
  partial: 'Reading, in part',
  refused: 'Refused by the vendor',
  no_access: 'No access',
  rate_limited: 'Rate limited',
  unreachable: 'Unreachable',
  error: 'Error',
};

export function feedStatusText(status: string): string {
  return status ? (FEED_STATUS_LABELS[status] ?? status) : 'Not polled yet';
}

export function merakiAlertRow(a: MerakiAlert): AlertFeedRow {
  return {
    key: a.alert_key,
    severity: a.severity,
    status: a.status,
    title: a.title,
    message: a.message,
    subject: a.device_name || a.device_serial || '-',
    where: a.network_name,
    source: a.org_name || String(a.org_ref),
    startedAt: a.started_at,
    lastAt: a.status === 'resolved' ? a.resolved_at : a.last_seen,
    via: a.seen_via.join(', '),
    alertVia: a.alert_via,
    muted: Boolean(a.muted),
  };
}

export function vendorAlertRow(a: VendorAlert): AlertFeedRow {
  return {
    key: a.alert_key,
    severity: a.severity,
    status: a.status,
    title: a.title,
    message: a.message,
    subject: a.entity_name || a.entity_id || '-',
    where: a.site && a.site !== a.entity_name ? a.site : '',
    source: a.org_name || String(a.org_ref),
    startedAt: a.started_at,
    lastAt: a.status === 'resolved' ? a.resolved_at : a.last_seen,
    via: a.event_sub_type || a.event_type,
    alertVia: a.alert_via,
    muted: Boolean(a.muted),
  };
}

export interface PollOutcome {
  ok: boolean;
  polled: number;
  failed?: number;
  new?: number;
  resolved?: number;
  error?: string;
}

/**
 * The message shown after Poll Now. ``noun`` names a source (organization,
 * account); ``settingsWhere`` is where the per-source errors are shown.
 */
export function pollSummary(r: PollOutcome, noun: string, settingsWhere = 'Topology > Sources'): string {
  if (r.ok) return `Polled ${r.polled} ${noun}(s): ${r.new ?? 0} new, ${r.resolved ?? 0} resolved.`;
  if (r.error) return `Poll failed: ${r.error}.`;
  return `Polled ${r.polled} ${noun}(s); ${r.failed ?? 0} failed. See ${settingsWhere} for the error.`;
}
