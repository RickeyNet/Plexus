import type {
  EventReceiverConfig,
  EventReceiverSettings,
  SyslogStreamKind,
  SyslogTlsGenerate,
  SyslogTlsState,
} from '@/api/settings';
import type { SummaryStripItem } from '@/components/SummaryStrip';
import { formatCount } from '@/lib/formatCount';
import { formatBackendDate, formatRelativeTime, toDate } from '@/lib/datetime';

/** `syslog` is the UDP syslog listener; `syslog_tcp` and `syslog_tls` are the stream listeners. */
export type ReceiverKind = 'syslog' | SyslogStreamKind | 'trap';

/** In the order the tab and the save summary list them. */
export const RECEIVER_KINDS: readonly ReceiverKind[] = ['syslog', 'syslog_tcp', 'syslog_tls', 'trap'];

export const RECEIVER_LABEL: Record<ReceiverKind, string> = {
  syslog: 'Syslog over UDP',
  syslog_tcp: 'Syslog over TCP',
  syslog_tls: 'Syslog over TLS',
  trap: 'SNMP traps',
};

/** The protocol each listener binds its port on (TLS runs over TCP). */
export const RECEIVER_PROTOCOL: Record<ReceiverKind, 'UDP' | 'TCP'> = {
  syslog: 'UDP',
  syslog_tcp: 'TCP',
  syslog_tls: 'TCP',
  trap: 'UDP',
};

export const RECEIVER_DEFAULT_PORT: Record<ReceiverKind, number> = {
  syslog: 1514,
  syslog_tcp: 1514,
  syslog_tls: 6514,
  trap: 10162,
};

export function isStreamKind(kind: ReceiverKind): kind is SyslogStreamKind {
  return kind === 'syslog_tcp' || kind === 'syslog_tls';
}

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
    syslog_tcp_enabled: cfg.syslog_tcp_enabled,
    syslog_tcp_port: cfg.syslog_tcp_port,
    syslog_tls_enabled: cfg.syslog_tls_enabled,
    syslog_tls_port: cfg.syslog_tls_port,
    syslog_tls_require_client_cert: cfg.syslog_tls_require_client_cert,
    syslog_tls_match_client_cert: cfg.syslog_tls_match_client_cert,
    syslog_udp_actions: cfg.syslog_udp_actions,
    trap_alerts: cfg.trap_alerts,
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

type PortField = `${ReceiverKind}_port`;

/** Field errors keyed by port field; empty when the ports can be saved. */
export function validateReceiverPorts(s: EventReceiverSettings): Partial<Record<PortField, string>> {
  const errors: Partial<Record<PortField, string>> = {};
  for (const kind of RECEIVER_KINDS) {
    const error = portError(s[`${kind}_port`]);
    if (error) errors[`${kind}_port`] = error;
  }
  if (!errors.syslog_port && !errors.trap_port && s.syslog_enabled && s.trap_enabled && s.syslog_port === s.trap_port) {
    errors.trap_port = 'Use a different port from the UDP syslog receiver.';
  }
  // TCP and UDP may share a port number; the two TCP listeners may not.
  if (
    !errors.syslog_tcp_port
    && !errors.syslog_tls_port
    && s.syslog_tcp_enabled
    && s.syslog_tls_enabled
    && s.syslog_tcp_port === s.syslog_tls_port
  ) {
    errors.syslog_tls_port = 'Use a different port from the TCP syslog receiver.';
  }
  return errors;
}

/** What the TLS certificate section holds, as far as the receiver settings depend on it. */
export type TlsStored = Pick<SyslogTlsState, 'has_certificate' | 'has_client_ca'>;

type GuardField =
  | 'syslog_tls_enabled'
  | 'syslog_tls_require_client_cert'
  | 'syslog_tls_match_client_cert'
  | 'syslog_udp_actions';

/**
 * The server's refusals that the form can see coming, keyed by the switch
 * they are about. `saved` is the stored settings: turning a switch on is
 * checked, not a switch that was already on. `tls` is undefined until the
 * certificate state has loaded, and then the certificate checks are left
 * to the server.
 */
export function receiverGuards(
  draft: EventReceiverSettings,
  saved: EventReceiverSettings,
  tls: TlsStored | undefined,
): Partial<Record<GuardField, string>> {
  const errors: Partial<Record<GuardField, string>> = {};
  if (tls && draft.syslog_tls_enabled && !saved.syslog_tls_enabled && !tls.has_certificate) {
    errors.syslog_tls_enabled =
      'Store or generate a server certificate under TLS certificate before turning on the TLS receiver.';
  }
  if (
    tls
    && draft.syslog_tls_require_client_cert
    && !saved.syslog_tls_require_client_cert
    && !tls.has_client_ca
  ) {
    errors.syslog_tls_require_client_cert = 'Store a client CA under Client certificates before requiring client certificates.';
  }
  if (draft.syslog_tls_match_client_cert && !draft.syslog_tls_require_client_cert) {
    errors.syslog_tls_match_client_cert =
      'Require client certificates before requiring that the certificate names the host.';
  }
  if (!draft.syslog_udp_actions && !draft.syslog_tcp_enabled && !draft.syslog_tls_enabled) {
    errors.syslog_udp_actions = 'Turn on the syslog TCP or TLS receiver before turning off actions on UDP messages.';
  }
  return errors;
}

/** One line per receiver for the save status: off, listening, or why it did not start. */
export function saveSummary(saved: EventReceiverConfig): string {
  const parts = RECEIVER_KINDS.map((kind) => {
    const label = RECEIVER_LABEL[kind];
    if (!saved[`${kind}_enabled`]) return `${label} off`;
    const port = `${RECEIVER_PROTOCOL[kind]} ${saved[`${kind}_port`]}`;
    if (saved[`${kind}_running`]) return `${label} listening on ${port}`;
    const why = isStreamKind(kind) ? saved[`${kind}_error`] : '';
    return why ? `${label} did not start: ${why.replace(/\.$/, '')}` : `${label} failed to start on ${port} (check the logs)`;
  });
  return `Receiver settings saved: ${parts.join(', ')}.`;
}

/** Counters of one receiver since it last started, for a SummaryStrip. */
export function receiverCounters(cfg: EventReceiverConfig, kind: ReceiverKind, now: number = Date.now()): SummaryStripItem[] {
  const errors = cfg[`${kind}_errors`] ?? 0;
  const items: SummaryStripItem[] = [
    { label: 'Received', value: formatCount(cfg[`${kind}_received`]) },
    {
      label: 'Last message',
      value: formatRelativeTime(cfg[`${kind}_last_message_at`] || null, now, 'None yet'),
    },
  ];
  if (!isStreamKind(kind)) {
    items.push({ label: 'Unreadable', value: formatCount(errors), tone: errors > 0 ? 'warning' : undefined });
    if (kind === 'trap') {
      // Traps from inventory hosts dropped since Plexus started: not the
      // host's SNMP community, or an SNMPv3 trap failing its USM checks.
      const community = cfg.trap_dropped_community ?? 0;
      const v3 = cfg.trap_dropped_v3 ?? 0;
      items.push(
        { label: 'Wrong community', value: formatCount(community), tone: community > 0 ? 'warning' : undefined },
        { label: 'SNMPv3 refused', value: formatCount(v3), tone: v3 > 0 ? 'warning' : undefined },
      );
    }
    return items;
  }
  // Stream errors also count framing errors and failed TLS handshakes.
  items.push(
    { label: 'Errors', value: formatCount(errors), tone: errors > 0 ? 'warning' : undefined },
    { label: 'Open connections', value: formatCount(cfg[`${kind}_connections`]) },
    { label: 'Connections refused', value: formatCount(cfg[`${kind}_connections_refused`]) },
  );
  if (kind === 'syslog_tls') {
    const certRefused = cfg.syslog_tls_connections_cert_refused ?? 0;
    items.push({
      label: 'Certificate not for host',
      value: formatCount(certRefused),
      tone: certRefused > 0 ? 'warning' : undefined,
    });
  }
  return items;
}

// --- TLS certificate ---

const DAY_MS = 86_400_000;

/** A certificate this close to its end is flagged. */
export const EXPIRY_WARNING_DAYS = 30;

export interface CertificateExpiry {
  state: 'valid' | 'expiring' | 'expired';
  /** Whole days left; negative once expired. */
  days: number;
  text: string;
}

/** How a certificate's end date reads: expired, expiring within 30 days, or valid. */
export function certificateExpiry(notAfter: string, now: number = Date.now()): CertificateExpiry {
  const end = toDate(notAfter);
  const date = formatBackendDate(notAfter);
  if (!end) return { state: 'valid', days: 0, text: `Valid until ${date}` };
  const left = end.getTime() - now;
  const days = Math.floor(left / DAY_MS);
  if (left <= 0) return { state: 'expired', days, text: `Expired on ${date}` };
  if (days < EXPIRY_WARNING_DAYS) {
    const span = days === 0 ? 'less than a day' : days === 1 ? '1 day' : `${days} days`;
    return { state: 'expiring', days, text: `Expires in ${span}, on ${date}` };
  }
  return { state: 'valid', days, text: `Valid until ${date}` };
}

/** The names of a generated certificate: one per line or comma separated, blanks and repeats dropped. */
export function parseSanList(text: string): string[] {
  const seen = new Set<string>();
  for (const part of text.split(/[\s,]+/)) {
    const name = part.trim();
    if (name) seen.add(name);
  }
  return [...seen];
}

export interface GenerateForm {
  commonName: string;
  sans: string;
  days: number;
}

export const DEFAULT_CERT_DAYS = 825;
export const MAX_SANS = 32;

export type GenerateErrors = Partial<Record<keyof GenerateForm, string>>;

/** The checks the generate endpoint makes on its bounds (the server checks each name). */
export function validateGenerate(form: GenerateForm): GenerateErrors {
  const errors: GenerateErrors = {};
  const cn = form.commonName.trim();
  if (!cn) errors.commonName = 'Enter the name devices use to reach Plexus.';
  else if (cn.length > 64) errors.commonName = 'Use at most 64 characters.';
  if (parseSanList(form.sans).length > MAX_SANS) errors.sans = `List at most ${MAX_SANS} names and addresses.`;
  if (!Number.isInteger(form.days) || form.days < 1 || form.days > 3650) {
    errors.days = 'Enter a whole number of days from 1 to 3650.';
  }
  return errors;
}

export function generateBody(form: GenerateForm): SyslogTlsGenerate {
  return { common_name: form.commonName.trim(), sans: parseSanList(form.sans), days: form.days };
}

/** The upload of a server certificate: both PEMs, or a reason to fill in the missing one. */
export function uploadBody(certPem: string, keyPem: string): { cert_pem: string; key_pem: string } | string {
  const cert = certPem.trim();
  const key = keyPem.trim();
  if (!cert && !key) return 'Paste the certificate and its private key.';
  if (!cert) return 'Paste the certificate that belongs to this private key.';
  if (!key) return 'Paste the private key of this certificate.';
  return { cert_pem: cert, key_pem: key };
}

/**
 * The client CA save: the pasted PEM, '' to remove it, or the reason it
 * cannot be removed while the saved settings require client certificates.
 */
export function clientCaBody(text: string, requireClientCert: boolean): { client_ca_pem: string } | string {
  const pem = text.trim();
  if (!pem && requireClientCert) {
    return 'Turn off Require client certificates and save the receiver settings before removing the client CA.';
  }
  return { client_ca_pem: pem };
}

/** A data URL that downloads a PEM as a file; nothing is fetched. */
export function pemDownloadHref(pem: string): string {
  return `data:application/x-pem-file;charset=utf-8,${encodeURIComponent(pem)}`;
}
