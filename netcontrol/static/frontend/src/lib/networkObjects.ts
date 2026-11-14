/**
 * Pure helpers for the VRF and VLAN records and interface addresses: the
 * VLAN list query, the site filter's select values, address formatting,
 * the VLAN id parser and the host dialog's VRF / VLAN keys.
 */
import type { InterfaceAddress } from '@/api/networkObjects';

/** The VLAN ids a record may take. */
export const VID_MIN = 1;
export const VID_MAX = 4094;
export const VRF_NAME_MAX = 64;
export const VRF_RD_MAX = 64;
export const VLAN_NAME_MAX = 64;

// ── VLAN site filter ───────────────────────────────────────────────────────

/** All VLANs, the VLANs of no site, or those of one site (its id). */
export type VlanSiteFilter = 'all' | 'none' | number;

/** The VLAN list URL for a site filter (and an optional VLAN id). */
export function vlanListPath(site: VlanSiteFilter, vid?: number): string {
  const params = new URLSearchParams();
  if (site !== 'all') params.set('site_id', String(site));
  if (vid !== undefined) params.set('vid', String(vid));
  const qs = params.toString();
  return `/ipam/vlans${qs ? `?${qs}` : ''}`;
}

/** The `<select>` value of a site filter. */
export function siteFilterToSelect(site: VlanSiteFilter): string {
  return String(site);
}

/** The site filter a `<select>` value names; anything unknown is 'all'. */
export function siteFilterFromSelect(value: string): VlanSiteFilter {
  if (value === 'none') return 'none';
  const n = Number(value);
  return value !== '' && Number.isInteger(n) && n > 0 ? n : 'all';
}

// ── VLAN id ────────────────────────────────────────────────────────────────

/** The VLAN id typed in a field, or null when it is not a whole number from 1 to 4094. */
export function parseVid(text: string): number | null {
  const t = text.trim();
  if (!/^\d+$/.test(t)) return null;
  const n = Number(t);
  return n >= VID_MIN && n <= VID_MAX ? n : null;
}

// ── Interface addresses ────────────────────────────────────────────────────

/** `192.0.2.1/24`. */
export function formatInterfaceAddress(a: Pick<InterfaceAddress, 'address' | 'prefix_length'>): string {
  return `${a.address}/${a.prefix_length}`;
}

/** "Primary", "Secondary", "Virtual (HSRP)". */
export function addressRoleLabel(a: Pick<InterfaceAddress, 'role' | 'protocol'>): string {
  const role = a.role ? a.role.charAt(0).toUpperCase() + a.role.slice(1) : 'Unknown';
  return a.protocol ? `${role} (${a.protocol})` : role;
}

/** The VRF as shown in a table: "Global" for ''. */
export function vrfLabel(name: string | null | undefined): string {
  return name ? name : 'Global';
}

/** Interface addresses grouped by address, for annotating address rows. */
export function interfacesByAddress<T extends Pick<InterfaceAddress, 'address'>>(rows: readonly T[]): Map<string, T[]> {
  const out = new Map<string, T[]>();
  for (const row of rows) {
    const list = out.get(row.address);
    if (list) list.push(row);
    else out.set(row.address, [row]);
  }
  return out;
}

/** "edge-1 Vlan10", or the first one plus "and N more" when several interfaces carry the address. */
export function describeCarriers(rows: readonly Pick<InterfaceAddress, 'hostname' | 'interface'>[]): string {
  if (rows.length === 0) return '';
  const first = `${rows[0].hostname} ${rows[0].interface}`;
  return rows.length === 1 ? first : `${first} and ${rows.length - 1} more`;
}

// ── Host dialog ────────────────────────────────────────────────────────────

export interface HostNetworkFields {
  vrf_name?: string;
  vlan_id?: string;
}

/**
 * The `vrf_name` / `vlan_id` keys a host create or update sends. `initial`
 * is what the host row carries (undefined keys: the row does not say).
 * On create every typed value is sent. On edit nothing is sent unless a
 * value changed; then both keys go when both are known (the server sets
 * them together), else only the typed one.
 */
export function hostNetworkBody(
  initial: { vrf_name?: string | null; vlan_id?: string | number | null } | null,
  vrf: string,
  vlan: string,
): HostNetworkFields {
  const v = vrf.trim();
  const l = vlan.trim();
  if (initial === null) {
    const out: HostNetworkFields = {};
    if (v) out.vrf_name = v;
    if (l) out.vlan_id = l;
    return out;
  }
  const knownVrf = initial.vrf_name !== undefined;
  const knownVlan = initial.vlan_id !== undefined;
  const startVrf = (initial.vrf_name ?? '').trim();
  const startVlan = String(initial.vlan_id ?? '').trim();
  const vrfChanged = knownVrf ? v !== startVrf : v !== '';
  const vlanChanged = knownVlan ? l !== startVlan : l !== '';
  if (!vrfChanged && !vlanChanged) return {};
  const out: HostNetworkFields = {};
  if (vrfChanged || knownVrf) out.vrf_name = v;
  if (vlanChanged || knownVlan) out.vlan_id = l;
  return out;
}
