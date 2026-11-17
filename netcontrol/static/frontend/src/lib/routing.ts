import { parseIpNetwork } from '@/lib/ipNetwork';
import type { Tone } from '@/lib/severity';

/**
 * Routing objects (the intended BGP state of devices): the rules the forms
 * check before the server does (`netcontrol/routing.py` is the authority),
 * and the labels and tones of statuses and compliance states.
 */

export const ASN_MIN = 1;
export const ASN_MAX = 4294967295;
export const ROUTING_NAME_MAX = 64;
export const POLICY_MAX = 200;

/** The address families a peering may carry (as `netcontrol/routing.py` lists them). */
export const ADDRESS_FAMILIES = [
  'ipv4-unicast',
  'ipv4-multicast',
  'ipv4-labeled-unicast',
  'ipv4-flowspec',
  'ipv6-unicast',
  'ipv6-multicast',
  'ipv6-labeled-unicast',
  'ipv6-flowspec',
  'vpnv4-unicast',
  'vpnv6-unicast',
  'l2vpn-evpn',
  'l2vpn-vpls',
  'link-state',
  'rtc',
] as const;

export const INSTANCE_STATUSES = ['planned', 'active', 'decommissioned'] as const;
export const PEERING_STATUSES = ['planned', 'active', 'disabled', 'decommissioned'] as const;

export const COMPLIANCE_STATES = ['matched', 'down', 'missing', 'unexpected', 'asn_mismatch', 'no_data'] as const;
export type ComplianceState = (typeof COMPLIANCE_STATES)[number];

const STATE_LABELS: Record<ComplianceState, string> = {
  matched: 'Matched',
  down: 'Down',
  missing: 'Missing',
  unexpected: 'Unexpected',
  asn_mismatch: 'ASN mismatch',
  no_data: 'No data',
};

const STATE_TONES: Record<ComplianceState, Tone> = {
  matched: 'success',
  down: 'danger',
  missing: 'warning',
  unexpected: 'info',
  asn_mismatch: 'danger',
  no_data: 'neutral',
};

const STATE_HELP: Record<ComplianceState, string> = {
  matched: 'Intended and observed, session established.',
  down: 'Intended and observed, but the session is not established.',
  missing: 'Intended (active) but not among the observed BGP neighbors.',
  unexpected: 'Observed BGP neighbor with no intended peering.',
  asn_mismatch: 'Observed with a different remote AS than intended.',
  no_data: 'Neighbor discovery has not run for this device, so nothing can be compared.',
};

export function complianceStateLabel(state: string): string {
  return STATE_LABELS[state as ComplianceState] ?? state;
}

export function complianceStateTone(state: string): Tone {
  return STATE_TONES[state as ComplianceState] ?? 'neutral';
}

export function complianceStateHelp(state: string): string {
  return STATE_HELP[state as ComplianceState] ?? '';
}

const STATUS_TONES: Record<string, Tone> = {
  active: 'success',
  planned: 'info',
  disabled: 'warning',
  decommissioned: 'neutral',
};

export function statusTone(status: string): Tone {
  return STATUS_TONES[status] ?? 'neutral';
}

export function statusLabel(status: string): string {
  return status ? status[0].toUpperCase() + status.slice(1) : '-';
}

/**
 * An AS number from asplain (`65001`, `AS65001`) or asdot (`1.10`) text, or
 * null when it is not one from 1 to 4294967295.
 */
export function parseAsn(text: string): number | null {
  let t = text.trim();
  if (/^as/i.test(t)) t = t.slice(2).trim();
  let value: number | null = null;
  if (/^\d+$/.test(t)) value = Number(t);
  else {
    const dot = /^(\d+)\.(\d+)$/.exec(t);
    if (dot) {
      const high = Number(dot[1]);
      const low = Number(dot[2]);
      value = high <= 65535 && low <= 65535 ? high * 65536 + low : null;
    }
  }
  return value !== null && Number.isSafeInteger(value) && value >= ASN_MIN && value <= ASN_MAX ? value : null;
}

/** `AS65001`. */
export function formatAsn(asn: number | null | undefined): string {
  return asn === null || asn === undefined ? '-' : `AS${asn}`;
}

/** 4 or 6 for a bare IPv4 / IPv6 address (no prefix length), null for anything else. */
export function ipVersion(text: string): 4 | 6 | null {
  const t = text.trim();
  if (t.includes('/')) return null;
  return parseIpNetwork(t)?.version ?? null;
}

/**
 * The form errors of a peering's addresses: the remote address is required,
 * each must be an IP address, and both of one family.
 */
export function peeringAddressErrors(local: string, remote: string): { local?: string; remote?: string } {
  const out: { local?: string; remote?: string } = {};
  const rv = remote.trim() ? ipVersion(remote) : null;
  const lv = local.trim() ? ipVersion(local) : null;
  if (!remote.trim()) out.remote = 'Remote address is required.';
  else if (rv === null) out.remote = 'Remote address must be an IPv4 or IPv6 address.';
  if (local.trim() && lv === null) out.local = 'Local address must be an IPv4 or IPv6 address.';
  else if (lv !== null && rv !== null && lv !== rv) out.local = 'Local and remote addresses must both be IPv4 or both be IPv6.';
  return out;
}

/** A router id error: empty is fine, otherwise a dotted IPv4 address. */
export function routerIdError(text: string): string | undefined {
  return text.trim() && ipVersion(text) !== 4 ? 'Router ID must be an IPv4 address (dotted quad).' : undefined;
}
