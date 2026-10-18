import type {
  MerakiSubnet,
  PathTraceQuery,
  PathVerdict,
  ReachabilityQuery,
  ReachabilityReport,
  ReachabilityRow,
  TopologySource,
} from '@/api/meraki';

import { INVENTORY_ORG_REF, providerLabel, PROVIDER_INVENTORY } from './helpers';
import { parseTraffic } from './paths';

// Reachability sweep: one destination traced from every source network the
// filters keep (`GET /api/topology/reachability`). These helpers turn the
// form into the query and the rows into chips and a per-site rollup;
// Reachability.tsx draws them. The downloads (spreadsheet, CSV) come from
// the server with the same query (`reachabilityFileUrl`).

/** Subnet kinds a sweep can start from, with their names, in display order. */
export const SWEEP_KINDS: { key: string; label: string }[] = [
  { key: 'vlan', label: 'VLANs' },
  { key: 'lan', label: 'Single LANs' },
  { key: 'svi', label: 'Switch SVIs' },
  { key: 'range', label: 'Cato site ranges' },
  { key: 'subnet', label: 'Cloud subnets' },
  { key: 'connected', label: 'Firewall interfaces' },
  { key: 'static', label: 'Static routes' },
  { key: 'vpn', label: 'VPN local networks' },
  { key: 'peer', label: 'Behind VPN peers' },
  { key: 'pool', label: 'RA VPN pools' },
  { key: 'host', label: 'Cloud VM addresses' },
  { key: 'user', label: 'Remote users' },
];

/** The kinds the server sweeps when none are named: the networks endpoints live in. */
export const DEFAULT_SWEEP_KINDS = ['vlan', 'lan', 'svi', 'range', 'subnet', 'connected'];

export const SWEEP_PROVIDERS = ['meraki', 'cato', 'fmc', 'panorama', 'appgate', 'aws', 'azure', 'gcp'];

// Snapshot sources are filtered by id (org_ref); the clouds by provider, since
// their accounts are not map sources.
const SNAPSHOT_SOURCE_TYPES = ['meraki', 'cato', 'fmc', 'panorama', 'appgate'];

function hasInventorySubnets(subnets: MerakiSubnet[]): boolean {
  return subnets.some((s) => s.provider === PROVIDER_INVENTORY);
}

/** The Providers checkboxes: inventory hosts too once the index has their networks. */
export function sweepProviders(subnets: MerakiSubnet[]): string[] {
  return hasInventorySubnets(subnets) ? [...SWEEP_PROVIDERS, PROVIDER_INVENTORY] : SWEEP_PROVIDERS;
}

export interface SweepSourceOption {
  key: string;
  /** The org_ref the `sources` filter names. */
  id: number;
  label: string;
}

/** The Sources options: the snapshot sources, and the inventory once the index has its networks. */
export function sweepSources(sources: TopologySource[], subnets: MerakiSubnet[]): SweepSourceOption[] {
  const options: SweepSourceOption[] = [];
  for (const s of sources) {
    if (s.id !== null && SNAPSHOT_SOURCE_TYPES.includes(s.type)) {
      options.push({ key: s.key, id: s.id, label: `${s.name} (${providerLabel(s.type)})` });
    }
  }
  if (hasInventorySubnets(subnets)) {
    options.push({ key: PROVIDER_INVENTORY, id: INVENTORY_ORG_REF, label: providerLabel(PROVIDER_INVENTORY) });
  }
  return options;
}

/** Verdicts in the order the chips and the rollup show them. */
export const VERDICT_ORDER: PathVerdict[] = ['allowed', 'blocked', 'unreachable', 'partial', 'unknown'];

export interface ReachabilityForm {
  destination: string;
  /** Set when the destination was picked from the subnet suggestions. */
  destinationOrgRef?: number;
  destinationNodeId?: string;
  /** `tcp/445`, `udp 53`, `icmp`, empty for any traffic (Path Mode's syntax). */
  traffic: string;
  sources: number[];
  providers: string[];
  kinds: string[];
  vlans: string;
  name: string;
  exclude: string;
  sites: string;
  within: string;
  /** '' either, '1' advertised into the VPN, '0' not. */
  inVpn: '' | '1' | '0';
}

export function emptyForm(): ReachabilityForm {
  return {
    destination: '',
    traffic: 'tcp/445',
    sources: [],
    providers: [],
    kinds: [...DEFAULT_SWEEP_KINDS],
    vlans: '',
    name: '',
    exclude: '',
    sites: '',
    within: '',
    inVpn: '',
  };
}

/** Why the VLAN text (`100, 110-120`) is not valid, null when it is (or empty). */
export function vlanTextError(text: string): string | null {
  for (const raw of text.split(',')) {
    const part = raw.trim();
    if (!part) continue;
    const match = /^(\d{1,4})(?:\s*-\s*(\d{1,4}))?$/.exec(part);
    if (!match) return `"${part}" is not a VLAN id or range (such as 100 or 110-120).`;
    const low = Number(match[1]);
    const high = Number(match[2] ?? match[1]);
    if (low > high || high > 4095) return `"${part}" is not a VLAN range from 0 to 4095.`;
  }
  return null;
}

/** The query of a form, or the reason it cannot be run. */
export function buildReachabilityQuery(form: ReachabilityForm): { query: ReachabilityQuery } | { error: string } {
  const destination = form.destination.trim();
  if (!destination) return { error: 'Enter a destination address or network.' };
  const traffic = parseTraffic(form.traffic);
  if (!traffic) return { error: 'Traffic must be like tcp/445, udp 53, icmp, or empty for any traffic.' };
  const vlanError = vlanTextError(form.vlans);
  if (vlanError) return { error: vlanError };
  if (!form.kinds.length) return { error: 'Pick at least one kind of network.' };
  const kinds = sameSet(form.kinds, DEFAULT_SWEEP_KINDS) ? undefined : form.kinds.join(',');
  const query: ReachabilityQuery = {
    destination,
    protocol: traffic.protocol,
    port: traffic.port,
    sources: form.sources.length ? form.sources.join(',') : undefined,
    providers: form.providers.length ? form.providers.join(',') : undefined,
    kinds,
    vlans: form.vlans.trim() || undefined,
    name: form.name.trim() || undefined,
    exclude: form.exclude.trim() || undefined,
    sites: form.sites.trim() || undefined,
    within: form.within.trim() || undefined,
    in_vpn: form.inVpn || undefined,
  };
  if (form.destinationOrgRef !== undefined && form.destinationNodeId) {
    query.destination_org_ref = form.destinationOrgRef;
    query.destination_node_id = form.destinationNodeId;
  }
  return { query };
}

function sameSet(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((value) => b.includes(value));
}

/** The rows of one verdict, or every row for null. */
export function rowsWithVerdict(rows: ReachabilityRow[], verdict: PathVerdict | null): ReachabilityRow[] {
  return verdict ? rows.filter((row) => row.verdict === verdict) : rows;
}

export interface SiteRollup {
  site: string;
  checked: number;
  counts: Record<PathVerdict, number>;
}

function zeroCounts(): Record<PathVerdict, number> {
  return { allowed: 0, blocked: 0, unreachable: 0, partial: 0, unknown: 0 };
}

/** The rows per site (a row with no site is under the source's name), in the rows' order. */
export function siteRollup(rows: ReachabilityRow[]): SiteRollup[] {
  const sites = new Map<string, SiteRollup>();
  for (const row of rows) {
    const site = row.site_name || row.org_name || 'No site';
    let entry = sites.get(site);
    if (!entry) {
      entry = { site, checked: 0, counts: zeroCounts() };
      sites.set(site, entry);
    }
    entry.checked += 1;
    entry.counts[row.verdict] = (entry.counts[row.verdict] ?? 0) + 1;
  }
  return [...sites.values()];
}

/** The Path Mode trace of one row: its network to the sweep's destination. */
export function rowTraceQuery(row: ReachabilityRow, report: ReachabilityReport, query: ReachabilityQuery): PathTraceQuery {
  const destinationNode = report.destination.node;
  return {
    source: row.cidr,
    destination: report.destination.address || query.destination,
    source_node: row.source_node ?? undefined,
    destination_node: destinationNode === null || destinationNode === undefined ? undefined : destinationNode,
    protocol: query.protocol,
    port: query.port,
  };
}
