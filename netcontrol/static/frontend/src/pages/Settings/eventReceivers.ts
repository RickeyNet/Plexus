import type { EventReceiverConfig, EventReceiverSettings } from '@/api/settings';
import type { SummaryStripItem } from '@/components/SummaryStrip';
import { formatCount } from '@/lib/formatCount';
import { formatRelativeTime } from '@/lib/datetime';

export type ReceiverKind = 'syslog' | 'trap';

export const RECEIVER_LABEL: Record<ReceiverKind, string> = { syslog: 'Syslog', trap: 'SNMP traps' };

/** The saved settings only: the runtime fields are not sent back on save. */
export function receiverSettings(cfg: EventReceiverConfig): EventReceiverSettings {
  return {
    syslog_enabled: cfg.syslog_enabled,
    syslog_port: cfg.syslog_port,
    trap_enabled: cfg.trap_enabled,
    trap_port: cfg.trap_port,
    syslog_alerts: cfg.syslog_alerts,
    config_change_trigger: cfg.config_change_trigger,
    repoll_trigger: cfg.repoll_trigger,
    recollect_trigger: cfg.recollect_trigger,
    filterlog_evidence: cfg.filterlog_evidence,
  };
}

/** The OPNsense firewall log counters since Plexus started, as one sentence. */
export function filterlogSummary(cfg: EventReceiverConfig): string {
  const kept = cfg.filterlog_received ?? 0;
  const dropped = cfg.filterlog_dropped ?? 0;
  const unknown = cfg.filterlog_unknown_source ?? 0;
  const from = unknown > 0 ? ` (${formatCount(unknown)} from addresses that are no inventory host)` : '';
  return `OPNsense firewall log lines since Plexus started: ${formatCount(kept)} counted, ${formatCount(dropped)} dropped${from}.`;
}

function portError(port: number): string | undefined {
  return Number.isInteger(port) && port >= 1 && port <= 65535 ? undefined : 'Enter a port from 1 to 65535.';
}

/** Field errors keyed by port field; empty when the form can be saved. */
export function validateReceiverPorts(s: EventReceiverSettings): Partial<Record<'syslog_port' | 'trap_port', string>> {
  const errors: Partial<Record<'syslog_port' | 'trap_port', string>> = {};
  const syslog = portError(s.syslog_port);
  const trap = portError(s.trap_port);
  if (syslog) errors.syslog_port = syslog;
  if (trap) errors.trap_port = trap;
  if (!syslog && !trap && s.syslog_enabled && s.trap_enabled && s.syslog_port === s.trap_port) {
    errors.trap_port = 'Use a different port from the syslog receiver.';
  }
  return errors;
}

/** One line per enabled receiver for the save status: running, or failed to bind. */
export function saveSummary(saved: EventReceiverConfig): string {
  const parts = (['syslog', 'trap'] as const).map((kind) => {
    const label = RECEIVER_LABEL[kind];
    if (!saved[`${kind}_enabled`]) return `${label} off`;
    return saved[`${kind}_running`]
      ? `${label} listening on UDP ${saved[`${kind}_port`]}`
      : `${label} failed to start on UDP ${saved[`${kind}_port`]} (check the logs)`;
  });
  return `Receiver settings saved: ${parts.join(', ')}.`;
}

/** Counters of one receiver since it last started, for a SummaryStrip. */
export function receiverCounters(cfg: EventReceiverConfig, kind: ReceiverKind, now: number = Date.now()): SummaryStripItem[] {
  const errors = cfg[`${kind}_errors`] ?? 0;
  return [
    { label: 'Received', value: formatCount(cfg[`${kind}_received`]) },
    {
      label: 'Last message',
      value: formatRelativeTime(cfg[`${kind}_last_message_at`] || null, now, 'None yet'),
    },
    { label: 'Unreadable', value: formatCount(errors), tone: errors > 0 ? 'warning' : undefined },
  ];
}
