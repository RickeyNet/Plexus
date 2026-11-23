// Pure helpers of Monitoring -> Events, kept apart from the component so they
// can be unit tested.

import type { SyslogEvent } from '@/api/monitoring';

/**
 * The Type filter. The values are the stored `event_type` of
 * trap_syslog_events (`syslog`, `trap`), which GET /metrics/events filters on.
 */
export const EVENT_TYPES: { value: string; label: string }[] = [
  { value: 'syslog', label: 'Syslog' },
  { value: 'trap', label: 'SNMP Trap' },
];

/** The host column: the inventory hostname, else the host id, else the source address. */
export function eventHostLabel(e: Pick<SyslogEvent, 'hostname' | 'host_id' | 'source_ip'>): string {
  if (e.hostname) return e.hostname;
  if (e.host_id != null) return String(e.host_id);
  return e.source_ip || '-';
}

/**
 * The trap name of a stored trap message (`linkDown: ifIndex 12, ...` ->
 * `linkDown`); '' for an unknown trap (`SNMP trap <oid>: ...`) or a message
 * with no name.
 */
export function trapName(message: string | undefined): string {
  const text = message ?? '';
  const colon = text.indexOf(':');
  if (colon <= 0) return '';
  const head = text.slice(0, colon);
  return /^[A-Za-z][A-Za-z0-9]*$/.test(head) ? head : '';
}
