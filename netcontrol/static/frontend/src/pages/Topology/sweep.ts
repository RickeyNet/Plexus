import type {
  PathTraceQuery,
  PathVerdict,
  ReachabilityQuery,
  ReachabilityReport,
  ReachabilityRow,
} from '@/api/meraki';

import { parseTraffic } from './paths';
import { verdictLabel } from './pathTrace';

// Reachability sweep: one destination traced from every source network the
// filters keep (`GET /api/topology/reachability`). These helpers turn the
// form into the query and the rows into chips, a per-site rollup and CSV;
// Reachability.tsx draws them.

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

export const CSV_COLUMNS = [
  'Source',
  'Provider',
  'Site',
  'Network',
  'Kind',
  'VLAN',
  'CIDR',
  'In VPN',
  'Verdict',
  'Decided at',
  'Decided by',
  'Summary',
];

function csvCell(value: string): string {
  return /[",\r\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

/** Rows as CSV, with the server's columns (for downloading the rows shown). */
export function rowsToCsv(rows: ReachabilityRow[]): string {
  const lines = [CSV_COLUMNS.join(',')];
  for (const row of rows) {
    const cells = [
      row.org_name || String(row.org_ref ?? ''),
      row.provider,
      row.site_name,
      row.name,
      row.kind,
      row.vlan === null || row.vlan === undefined ? '' : String(row.vlan),
      row.cidr,
      row.in_vpn === null || row.in_vpn === undefined ? '' : row.in_vpn ? 'Yes' : 'No',
      verdictLabel(row.verdict).label,
      row.decided_at,
      row.decided_by,
      row.summary,
    ];
    lines.push(cells.map((cell) => csvCell(cell ?? '')).join(','));
  }
  return `${lines.join('\r\n')}\r\n`;
}

/** File name of a CSV of `report`: `reachability-10.0.10.20-tcp_445.csv`. */
export function csvFileName(report: Pick<ReachabilityReport, 'destination' | 'traffic'>, suffix = ''): string {
  const stem = `reachability-${report.destination.address}-${report.traffic}${suffix}`;
  return `${stem.replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '')}.csv`;
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
