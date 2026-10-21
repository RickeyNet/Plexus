import type {
  MerakiSubnet,
  NetworkRow,
  PathTraceQuery,
  PathVerdict,
  ReachabilityQuery,
  ReachabilityReport,
  ReachabilityRow,
  TopologySource,
} from '@/api/meraki';

import { INVENTORY_ORG_REF, providerLabel, PROVIDER_INVENTORY } from './helpers';
import { findSubnets, parseTraffic } from './paths';

// Reachability sweep: one destination traced from every source network the
// filters keep, or (matrix mode, no destination) every kept source traced to
// every destination network the `to` filters keep
// (`GET /api/topology/reachability`). A typed source (one address or network)
// replaces the source filters. These helpers turn the form into the
// query and the rows into chips and per-site or per-site-pair rollups;
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

/** The filters that pick a side's networks: the sources, or (matrix mode) the destinations. */
export interface SweepFilters {
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

export interface ReachabilityForm extends SweepFilters {
  /** One source (an IP address or network) in place of the source filters; empty: the filters apply. */
  source: string;
  /** Set when the source was picked from the subnet suggestions. */
  sourceOrgRef?: number;
  sourceNodeId?: string;
  /** Empty: matrix mode, every source traced to every network `to` keeps. */
  destination: string;
  /** Set when the destination was picked from the subnet suggestions. */
  destinationOrgRef?: number;
  destinationNodeId?: string;
  /** `tcp/445`, `udp 53`, `icmp`, empty for any traffic (Path Mode's syntax). */
  traffic: string;
  /** The destination networks, used when `destination` is empty. */
  to: SweepFilters;
}

export function emptyFilters(): SweepFilters {
  return {
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

export function emptyForm(): ReachabilityForm {
  return { source: '', destination: '', traffic: 'tcp/445', ...emptyFilters(), to: emptyFilters() };
}

/** The two typed ends of a sweep. */
export type SweepEnd = 'source' | 'destination';

/** The owner of a picked subnet, as the form keeps it. */
type EndOwner = Pick<MerakiSubnet, 'org_ref' | 'node_id'>;

/** The form fields of one typed end: its text and the owner of the subnet it stands for (cleared without one). */
export function endPatch(side: SweepEnd, text: string, owner?: EndOwner): Partial<ReachabilityForm> {
  return { ...(side === 'source' ? { source: text } : { destination: text }), ...endOwnerPatch(side, owner) };
}

/** The form fields of a picked owner only, leaving the end's text as it is. */
export function endOwnerPatch(side: SweepEnd, owner?: EndOwner): Partial<ReachabilityForm> {
  return side === 'source'
    ? { sourceOrgRef: owner?.org_ref, sourceNodeId: owner?.node_id }
    : { destinationOrgRef: owner?.org_ref, destinationNodeId: owner?.node_id };
}

/**
 * The form with each typed end that exactly one subnet holds placed at that
 * subnet's owner (as in Path Mode); an end with an owner already, or with
 * none or several subnets, is left as it is.
 */
export function withSingleOwners(form: ReachabilityForm, subnets: MerakiSubnet[]): ReachabilityForm {
  let next = form;
  for (const side of ['source', 'destination'] as const) {
    const ownerRef = side === 'source' ? next.sourceOrgRef : next.destinationOrgRef;
    if (ownerRef !== undefined) continue;
    const owners = findSubnets(next[side], subnets);
    if (owners.length === 1) next = { ...next, ...endOwnerPatch(side, owners[0]) };
  }
  return next;
}

/**
 * Every cloud subnet and Cato site range traced to every Meraki network with
 * any traffic, so each row lists the ports allowed end to end.
 */
export function cloudsToMerakiForm(): ReachabilityForm {
  return {
    ...emptyForm(),
    traffic: '',
    providers: ['aws', 'azure', 'gcp', 'cato'],
    to: { ...emptyFilters(), providers: ['meraki'] },
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

const FILTER_KEYS = ['sources', 'providers', 'kinds', 'vlans', 'name', 'exclude', 'sites', 'within', 'in_vpn'] as const;
type FilterKey = (typeof FILTER_KEYS)[number];

/** Why a filter block cannot be sent, null when it can. */
function filtersError(filters: SweepFilters): string | null {
  const vlanError = vlanTextError(filters.vlans);
  if (vlanError) return vlanError;
  if (!filters.kinds.length) return 'Pick at least one kind of network.';
  return null;
}

/** The query params of a filter block; the default kinds are left out. */
function filterParams(filters: SweepFilters): Record<FilterKey, string | undefined> {
  return {
    sources: filters.sources.length ? filters.sources.join(',') : undefined,
    providers: filters.providers.length ? filters.providers.join(',') : undefined,
    kinds: sameSet(filters.kinds, DEFAULT_SWEEP_KINDS) ? undefined : filters.kinds.join(','),
    vlans: filters.vlans.trim() || undefined,
    name: filters.name.trim() || undefined,
    exclude: filters.exclude.trim() || undefined,
    sites: filters.sites.trim() || undefined,
    within: filters.within.trim() || undefined,
    in_vpn: filters.inVpn || undefined,
  };
}

/** The destination filters as `to_*` params (matrix mode). */
function toFilterParams(filters: SweepFilters): Record<`to_${FilterKey}`, string | undefined> {
  const params = filterParams(filters);
  return Object.fromEntries(FILTER_KEYS.map((key) => [`to_${key}`, params[key]])) as Record<
    `to_${FilterKey}`,
    string | undefined
  >;
}

/** Whether a filter block keeps fewer than every network (an In VPN or Exclude choice alone does not count). */
function filtersNarrow(filters: SweepFilters): boolean {
  return Boolean(
    filters.sources.length ||
      filters.providers.length ||
      filters.name.trim() ||
      filters.sites.trim() ||
      filters.within.trim() ||
      filters.vlans.trim(),
  );
}

export const MATRIX_NARROW_ERROR =
  'Enter a source or a destination, or narrow the destination networks (a provider, source, site, name, VLAN or Within filter) to trace many destinations.';

/** Whether the form names one source, so the source filters are not used. */
export function isTypedSource(form: Pick<ReachabilityForm, 'source'>): boolean {
  return Boolean(form.source.trim());
}

/** The source side of a query: the typed source with its picked owner, or the source filter params. */
function sourceParams(form: ReachabilityForm): Partial<ReachabilityQuery> {
  const source = form.source.trim();
  if (!source) return filterParams(form);
  const params: Partial<ReachabilityQuery> = { source };
  if (form.sourceOrgRef !== undefined && form.sourceNodeId) {
    params.source_org_ref = form.sourceOrgRef;
    params.source_node_id = form.sourceNodeId;
  }
  return params;
}

/** The query of a form, or the reason it cannot be run. */
export function buildReachabilityQuery(form: ReachabilityForm): { query: ReachabilityQuery } | { error: string } {
  const destination = form.destination.trim();
  const typedSource = isTypedSource(form);
  const traffic = parseTraffic(form.traffic);
  if (!traffic) return { error: 'Traffic must be like tcp/445, udp 53, icmp, or empty for any traffic.' };
  // A typed source replaces the source filters, so they are neither checked nor sent.
  const sourceError = typedSource ? null : filtersError(form);
  if (sourceError) return { error: sourceError };
  const base = { protocol: traffic.protocol, port: traffic.port, ...sourceParams(form) };
  if (!destination) {
    // Matrix mode: the `to` filters pick the destinations. One typed source
    // times every network stays within the limit, so only many sources need
    // the destinations narrowed.
    if (!typedSource && !filtersNarrow(form.to)) return { error: MATRIX_NARROW_ERROR };
    const toError = filtersError(form.to);
    if (toError) return { error: `Destination networks: ${toError}` };
    return { query: { ...base, ...toFilterParams(form.to) } };
  }
  const query: ReachabilityQuery = { destination, ...base };
  if (form.destinationOrgRef !== undefined && form.destinationNodeId) {
    query.destination_org_ref = form.destinationOrgRef;
    query.destination_node_id = form.destinationNodeId;
  }
  return { query };
}

export const LIST_TYPED_SOURCE_ERROR = 'Clear Source to list the networks the Source networks filters keep.';

/**
 * The "List networks" query of a form: the source filters only, with
 * `list=1`, so the server lists the networks they keep without tracing them.
 * Refused while a source is typed, since the filters are not used then.
 */
export function buildListQuery(form: ReachabilityForm): { query: ReachabilityQuery } | { error: string } {
  if (isTypedSource(form)) return { error: LIST_TYPED_SOURCE_ERROR };
  const error = filtersError(form);
  if (error) return { error };
  // `protocol` is required by the type; empty, it is left out of the request.
  return { query: { list: '1', protocol: '', ...filterParams(form) } };
}

/** Whether a query only lists the networks the source filters keep. */
export function isListQuery(query: ReachabilityQuery): boolean {
  return query.list === '1';
}

/** Whether a query traces many destinations (no destination given). */
export function isMatrixQuery(query: ReachabilityQuery): boolean {
  return !isListQuery(query) && !query.destination?.trim();
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

/**
 * The site a rollup puts a network under: its site, else its source's name,
 * else (a typed end, which has neither) the node its trace starts or ends at.
 */
function siteOf(site: string, orgName: string, nodeLabel: string): string {
  return site || orgName || nodeLabel || 'No site';
}

function sourceSite(row: NetworkRow): string {
  return siteOf(row.site_name, row.org_name, row.node_label);
}

function destinationSite(row: ReachabilityRow): string {
  return siteOf(row.dst_site_name, row.dst_org_name, row.dst_node_label);
}

/** Whether a row was traced (one or matrix mode), not only listed. */
export function isTraceRow(row: NetworkRow): row is ReachabilityRow {
  return 'verdict' in row;
}

/**
 * Counts rows into the entry of their key, created by `make` on first sight,
 * in the rows' order; a listed (untraced) row counts as checked only.
 */
function rollUp<R extends NetworkRow, T extends { checked: number; counts: Record<PathVerdict, number> }>(
  rows: R[],
  keyOf: (row: R) => string,
  make: (row: R) => Omit<T, 'checked' | 'counts'>,
): T[] {
  const entries = new Map<string, T>();
  for (const row of rows) {
    const key = keyOf(row);
    let entry = entries.get(key);
    if (!entry) {
      entry = { ...make(row), checked: 0, counts: zeroCounts() } as T;
      entries.set(key, entry);
    }
    entry.checked += 1;
    if (isTraceRow(row)) entry.counts[row.verdict] = (entry.counts[row.verdict] ?? 0) + 1;
  }
  return [...entries.values()];
}

/** The rows per site (a row with no site is under the source's name), in the rows' order. */
export function siteRollup(rows: NetworkRow[]): SiteRollup[] {
  return rollUp<NetworkRow, SiteRollup>(rows, sourceSite, (row) => ({ site: sourceSite(row) }));
}

export interface PairRollup {
  source: string;
  destination: string;
  checked: number;
  counts: Record<PathVerdict, number>;
}

/** The rows per (source site, destination site) pair of a matrix sweep, in the rows' order. */
export function pairRollup(rows: ReachabilityRow[]): PairRollup[] {
  const pair = (row: ReachabilityRow) => ({
    source: sourceSite(row),
    destination: destinationSite(row),
  });
  return rollUp<ReachabilityRow, PairRollup>(
    rows,
    (row) => {
      const { source, destination } = pair(row);
      return JSON.stringify([source, destination]);
    },
    pair,
  );
}

/** The Path Mode trace of one row: its network to its destination. */
export function rowTraceQuery(row: ReachabilityRow, report: ReachabilityReport, query: ReachabilityQuery): PathTraceQuery {
  const matrix = report.mode === 'matrix' || !report.destination;
  const destinationNode = row.destination_node ?? (matrix ? null : report.destination?.node);
  return {
    source: row.cidr,
    destination: matrix ? row.dst_cidr : report.destination?.address || query.destination || row.dst_cidr,
    source_node: row.source_node ?? undefined,
    destination_node: destinationNode === null || destinationNode === undefined ? undefined : destinationNode,
    protocol: query.protocol,
    port: query.port,
  };
}
