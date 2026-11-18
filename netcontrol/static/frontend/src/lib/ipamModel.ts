/**
 * Display helpers for the IPAM namespaces, route targets, VLAN groups, RIRs
 * and aggregates (records served by /api/ipam, see `api/dcim.ts`).
 */

type Row = Record<string, unknown>;

/** The Global namespace every VRF and prefix is in unless moved (it cannot be deleted). */
export const GLOBAL_NAMESPACE_ID = 1;

/** `100-199`, or one id when the range holds one. */
export function vidRangeLabel(row: Row): string {
  const low = Number(row.min_vid ?? 1);
  const high = Number(row.max_vid ?? 4094);
  return low === high ? String(low) : `${low}-${high}`;
}

/** Where a VLAN group applies: a site, a region, or anywhere. */
export function vlanGroupScope(row: Row): string {
  if (row.site_id !== null && row.site_id !== undefined) return `Site ${String(row.site_name ?? row.site_id)}`;
  if (row.region_id !== null && row.region_id !== undefined) return `Region ${String(row.region_name ?? row.region_id)}`;
  return 'Any site';
}

/** A large address count in short form: 256, 65,536, 4.3 billion, 7.9e28. */
export function addressCount(value: unknown): string {
  const n = Number(value ?? 0);
  if (!Number.isFinite(n)) return '-';
  if (n < 1e9) return n.toLocaleString();
  if (n < 1e12) return `${(n / 1e9).toFixed(1)} billion`;
  return n.toExponential(1);
}

/** How much of an aggregate its prefixes cover: `75% (192 of 256 addresses)`. */
export function aggregateUsageLabel(row: Row): string {
  const pct = Number(row.utilization_pct ?? 0);
  return `${pct}% (${addressCount(row.used_addresses)} of ${addressCount(row.total_addresses)} addresses)`;
}
