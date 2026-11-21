import type { SecurityEvent } from '@/api/securityEvents';
import type { Tone } from '@/lib/severity';

/** The time windows the Security tab offers, in hours. */
export const SECURITY_WINDOWS: readonly { hours: number; label: string }[] = [
  { hours: 1, label: 'Last hour' },
  { hours: 24, label: 'Last 24 hours' },
  { hours: 24 * 7, label: 'Last 7 days' },
  { hours: 24 * 30, label: 'Last 30 days' },
];

export const SECURITY_SEVERITIES: readonly { value: string; label: string }[] = [
  { value: '', label: 'All severities' },
  { value: 'critical', label: 'Critical (priority 1)' },
  { value: 'warning', label: 'Warning (priority 2)' },
  { value: 'info', label: 'Info (priority 3+)' },
  { value: 'unknown', label: 'Unknown' },
];

export const SECURITY_ACTIONS: readonly { value: string; label: string }[] = [
  { value: '', label: 'Blocked or not' },
  { value: 'blocked', label: 'Blocked' },
  { value: 'allowed', label: 'Detected only' },
];

/** Rows per page of the event list. */
export const SECURITY_PAGE_SIZE = 100;

/** What the device did with the traffic: blocked, or only detected it. */
export function actionBadge(action: string | null | undefined): { text: string; tone: Tone } {
  if (action === 'blocked') return { text: 'Blocked', tone: 'success' };
  if (!action || action === 'allowed') return { text: 'Detected only', tone: 'warning' };
  return { text: action, tone: 'neutral' };
}

/** An address and port as one text: `192.0.2.1:80`, `[2001:db8::1]:443`. */
export function addressPort(address: string | null | undefined, port: number | null | undefined): string {
  const text = address || '-';
  if (port == null) return text;
  return text.includes(':') ? `[${text}]:${port}` : `${text}:${port}`;
}

/** The device an event came from: its inventory host, else its source. */
export function eventDevice(event: Pick<SecurityEvent, 'hostname' | 'source_name' | 'org_ref'>): string {
  return event.hostname || event.source_name || `Source ${event.org_ref}`;
}

/** "Showing 101-200 of 450" for a page of the list. */
export function pageLabel(offset: number, shown: number, total: number): string {
  if (!total || !shown) return `0 of ${total}`;
  return `Showing ${offset + 1}-${offset + shown} of ${total}`;
}
