import type { Circuit, CircuitStatus, CircuitTermination, TerminationInput, TermSide } from '@/api/circuits';
import type { Tone } from '@/lib/severity';

/** Limits the server applies (netcontrol/circuits.py). */
export const CIRCUIT_NAME_MAX = 100;
export const CIRCUIT_CID_MAX = 100;
export const CIRCUIT_TEXT_MAX = 200;
export const CIRCUIT_DESCRIPTION_MAX = 500;
export const CIRCUIT_COMMENTS_MAX = 10_000;
export const KBPS_MAX = 10_000_000_000;

export const TERM_SIDES: readonly TermSide[] = ['A', 'Z'];

export const CIRCUIT_STATUSES: readonly { value: CircuitStatus; label: string; tone: Tone }[] = [
  { value: 'planned', label: 'Planned', tone: 'info' },
  { value: 'provisioning', label: 'Provisioning', tone: 'primary' },
  { value: 'active', label: 'Active', tone: 'success' },
  { value: 'offline', label: 'Offline', tone: 'danger' },
  { value: 'deprovisioning', label: 'Deprovisioning', tone: 'warning' },
  { value: 'decommissioned', label: 'Decommissioned', tone: 'neutral' },
];

export function circuitStatusLabel(status: string): string {
  return CIRCUIT_STATUSES.find((s) => s.value === status)?.label ?? status;
}

export function circuitStatusTone(status: string): Tone {
  return CIRCUIT_STATUSES.find((s) => s.value === status)?.tone ?? 'neutral';
}

/** The list filters the circuits API takes; empty values are left out of the URL. */
export interface CircuitFilter {
  provider_id?: number;
  circuit_type_id?: number;
  status?: CircuitStatus;
  tenant_id?: number;
  site_id?: number;
  host_id?: number;
  q?: string;
}

/** A rate in kbps as people read it: `1.5 Gbps`, `100 Mbps`, `512 kbps`; `-` for none. */
export function formatKbps(kbps: number | null | undefined): string {
  if (kbps === null || kbps === undefined) return '-';
  const units: [number, string][] = [
    [1_000_000_000, 'Tbps'],
    [1_000_000, 'Gbps'],
    [1_000, 'Mbps'],
  ];
  for (const [size, unit] of units) {
    if (kbps >= size) return `${trimNumber(kbps / size)} ${unit}`;
  }
  return `${kbps} kbps`;
}

/** A rate in bits per second, via `formatKbps`. */
export function formatBps(bps: number): string {
  if (bps < 1000) return `${Math.round(bps)} bps`;
  return formatKbps(Math.round(bps / 1000));
}

function trimNumber(n: number): string {
  return Number.isInteger(n) ? String(n) : n.toFixed(n >= 100 ? 0 : n >= 10 ? 1 : 2).replace(/\.?0+$/, '');
}

/**
 * A kbps field's text as a number: `null` for empty, `undefined` when it is
 * not a whole number from 0 to `KBPS_MAX`.
 */
export function parseKbps(text: string): number | null | undefined {
  const t = text.trim();
  if (!t) return null;
  if (!/^\d+$/.test(t)) return undefined;
  const n = Number(t);
  return n <= KBPS_MAX ? n : undefined;
}

/** Where a termination ends: its site or provider network, then the device port. */
export function terminationSummary(t: CircuitTermination | undefined): string {
  if (!t) return '-';
  const where = t.site_name ?? t.provider_network_name ?? '-';
  if (!t.hostname) return where;
  return `${where} · ${t.hostname}${t.interface_name ? ` ${t.interface_name}` : ''}`;
}

export function terminationOf(circuit: Pick<Circuit, 'terminations'>, side: TermSide): CircuitTermination | undefined {
  return circuit.terminations.find((t) => t.term_side === side);
}

/** The editable fields of a termination, as the circuit dialog keeps them. */
export interface TerminationDraft {
  enabled: boolean;
  kind: 'site' | 'network';
  site_id: number | null;
  provider_network_id: number | null;
  host_id: number | null;
  interface_name: string;
  port_speed: string;
  upstream_speed: string;
  xconnect_id: string;
  pp_info: string;
  description: string;
}

export function terminationDraft(t: CircuitTermination | undefined): TerminationDraft {
  return {
    enabled: t !== undefined,
    kind: t?.provider_network_id ? 'network' : 'site',
    site_id: t?.site_id ?? null,
    provider_network_id: t?.provider_network_id ?? null,
    host_id: t?.host_id ?? null,
    interface_name: t?.interface_name ?? '',
    port_speed: t?.port_speed_kbps == null ? '' : String(t.port_speed_kbps),
    upstream_speed: t?.upstream_speed_kbps == null ? '' : String(t.upstream_speed_kbps),
    xconnect_id: t?.xconnect_id ?? '',
    pp_info: t?.pp_info ?? '',
    description: t?.description ?? '',
  };
}

/**
 * The local errors of a termination draft, keyed like the server's
 * (`terminations.<side>.<field>`), so the dialog shows both the same way.
 */
export function terminationErrors(side: TermSide, d: TerminationDraft): Record<string, string> {
  if (!d.enabled) return {};
  const p = `terminations.${side}.`;
  const errors: Record<string, string> = {};
  if (d.kind === 'site' && d.site_id === null) errors[`${p}site_id`] = 'Choose a site.';
  if (d.kind === 'network' && d.provider_network_id === null) errors[`${p}provider_network_id`] = 'Choose a provider network.';
  if (d.interface_name.trim() && d.host_id === null) errors[`${p}interface_name`] = 'Choose the device the interface belongs to.';
  if (parseKbps(d.port_speed) === undefined) errors[`${p}port_speed_kbps`] = 'Port speed must be a whole number of kbps.';
  if (parseKbps(d.upstream_speed) === undefined) errors[`${p}upstream_speed_kbps`] = 'Upstream speed must be a whole number of kbps.';
  return errors;
}

/** The API body of an enabled termination draft (only the chosen end is sent). */
export function terminationInput(side: TermSide, d: TerminationDraft): TerminationInput {
  return {
    term_side: side,
    site_id: d.kind === 'site' ? d.site_id : null,
    provider_network_id: d.kind === 'network' ? d.provider_network_id : null,
    host_id: d.host_id,
    interface_name: d.host_id === null ? '' : d.interface_name.trim(),
    port_speed_kbps: parseKbps(d.port_speed) ?? null,
    upstream_speed_kbps: parseKbps(d.upstream_speed) ?? null,
    xconnect_id: d.xconnect_id.trim(),
    pp_info: d.pp_info.trim(),
    description: d.description.trim(),
  };
}

/** `YYYY-MM-DD` that is a real date, or empty. */
export function isValidDate(text: string): boolean {
  const t = text.trim();
  if (!t) return true;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(t)) return false;
  const d = new Date(`${t}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === t;
}
