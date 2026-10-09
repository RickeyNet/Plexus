import type {
  PathDirection,
  PathHop,
  PathItem,
  PathItemStage,
  PathTraceQuery,
  PathVerdict,
  ReachabilityStatus,
} from '@/api/meraki';

import type { PathPick, PickLeg, TrafficFilter } from './paths';

// Path trace: what the server finds when it walks a Path Mode leg between two
// subnets or addresses hop by hop, through each device's routes, policies,
// ACLs, security groups and NAT, for the request and for the replies
// (`GET /api/topology/path`). These helpers turn picks into the query and the
// result into text, marks and map highlights; PathTrace.tsx draws them.

type NodeId = number | string;

/**
 * The trace of a leg from `from` to `to`, or null unless both ends are
 * subnets or addresses: a device or site pick has no address to trace.
 */
export function pathTraceQuery(from: PathPick, to: PathPick, traffic: TrafficFilter): PathTraceQuery | null {
  if (!from.subnet || !to.subnet) return null;
  return {
    source: from.address ?? from.subnet.cidr,
    destination: to.address ?? to.subnet.cidr,
    source_node: from.node,
    destination_node: to.node,
    protocol: traffic.protocol,
    port: traffic.port,
  };
}

/** The same traffic as a new connection from the destination to the source. */
export function reverseTraceQuery(query: PathTraceQuery): PathTraceQuery {
  return {
    source: query.destination,
    destination: query.source,
    source_node: query.destination_node,
    destination_node: query.source_node,
    protocol: query.protocol,
    port: query.port,
  };
}

export interface TraceHighlight {
  nodeIds: Set<NodeId>;
  edgeIds: Set<NodeId>;
}

/** The devices and links a traced direction passes, for the map. */
export function traceHighlight(direction: PathDirection | null | undefined): TraceHighlight {
  const nodeIds = new Set<NodeId>();
  const edgeIds = new Set<NodeId>();
  for (const hop of direction?.hops ?? []) {
    if (hop.node !== null && hop.node !== undefined) nodeIds.add(hop.node);
    if (hop.edge !== null && hop.edge !== undefined) edgeIds.add(hop.edge);
  }
  return { nodeIds, edgeIds };
}

/** Key of a leg among the legs of a path. */
export function legKey(leg: Pick<PickLeg, 'from' | 'to'>): string {
  return `${leg.from.key}|${leg.to.key}`;
}

/**
 * What the map highlights for a path: every pick, then per leg the hops of
 * its trace when it has some, else the path drawn over the links.
 */
export function mergeHighlights(
  picks: PathPick[],
  legs: PickLeg[],
  traces: Readonly<Record<string, TraceHighlight | null | undefined>>,
): TraceHighlight {
  const nodeIds = new Set<NodeId>(picks.map((p) => p.node));
  const edgeIds = new Set<NodeId>();
  for (const leg of legs) {
    const trace = traces[legKey(leg)];
    if (trace && trace.nodeIds.size) {
      for (const id of trace.nodeIds) nodeIds.add(id);
      for (const id of trace.edgeIds) edgeIds.add(id);
      continue;
    }
    for (const id of leg.path ?? []) nodeIds.add(id);
    for (const id of leg.edgeIds) edgeIds.add(id);
  }
  return { nodeIds, edgeIds };
}

const STAGES: Record<PathItemStage, string> = {
  policy: 'Policy',
  acl: 'ACL',
  security_group: 'Security group',
  nat: 'NAT',
  route: 'Route',
  link: 'Link',
  note: 'Note',
};

/** Name of the kind of step an item is. */
export function stageLabel(stage: PathItemStage | string): string {
  return STAGES[stage as PathItemStage] ?? stage;
}

const SUCCESS = 'var(--success, #2f9e44)';
const DANGER = 'var(--danger)';
const WARNING = 'var(--warning, #f59f00)';
const MUTED = 'var(--text-muted, #868e96)';

const MARKS: Record<ReachabilityStatus, { mark: string; color: string }> = {
  ok: { mark: '✓', color: SUCCESS },
  blocked: { mark: '✕', color: DANGER },
  partial: { mark: '◐', color: WARNING },
  unknown: { mark: '?', color: WARNING },
  info: { mark: 'i', color: MUTED },
};

/** The mark and colour of an item or hop status. */
export function statusMark(status: ReachabilityStatus | string): { mark: string; color: string } {
  return MARKS[status as ReachabilityStatus] ?? MARKS.unknown;
}

const VERDICTS: Record<PathVerdict, { label: string; color: string }> = {
  allowed: { label: 'Allowed', color: SUCCESS },
  blocked: { label: 'Blocked', color: DANGER },
  partial: { label: 'Allowed in part', color: WARNING },
  unknown: { label: 'Check incomplete', color: WARNING },
};

/** The words and colour of a verdict. */
export function verdictLabel(verdict: PathVerdict | string): { label: string; color: string } {
  return VERDICTS[verdict as PathVerdict] ?? VERDICTS.unknown;
}

/** The name of a hop: its label, else Internet for the Internet pseudo hop, else its node id. */
function hopName(hop: PathHop): string {
  return hop.label || (hop.node === null ? 'Internet' : String(hop.node));
}

/** A hop as a numbered line: `3. Hub 01 MX · Hub 01 · in AutoVPN from Branch 01 → out VLAN 20`. */
export function hopTitle(hop: PathHop, index: number): string {
  const parts = [hopName(hop)];
  if (hop.site && hop.site !== hop.label) parts.push(hop.site);
  const ports = [hop.in ? `in ${hop.in}` : '', hop.out ? `out ${hop.out}` : ''].filter(Boolean).join(' → ');
  if (ports) parts.push(ports);
  return `${index + 1}. ${parts.join(' · ')}`;
}

/**
 * The hops of a traced direction on one line, each not ok with its mark:
 * `Branch 01 MX → Hub 01 MX → Corp East Backup ✕ (3 hops)`. The count is the
 * number of devices listed (the numbered hops below it), not the links between
 * them. Null when there are no hops.
 */
export function traceRoute(direction: PathDirection | null | undefined): string | null {
  const hops = direction?.hops ?? [];
  if (!hops.length) return null;
  const names = hops.map((hop) => (hop.status === 'ok' ? hopName(hop) : `${hopName(hop)} ${statusMark(hop.status).mark}`));
  return `${names.join(' → ')} (${hops.length} hop${hops.length !== 1 ? 's' : ''})`;
}

/**
 * The hops of a traced direction as a plain way: `Branch 01 MX → Hub 01 MX`,
 * with no marks and no count, for a sentence that compares two directions.
 * Empty when there are no hops.
 */
export function traceWay(direction: PathDirection | null | undefined): string {
  return (direction?.hops ?? []).map(hopName).join(' → ');
}

/**
 * Where an item looked: the rule set, table or gateway. The rule that matched
 * is not repeated here, since an item's text names it (`Rule 2 (...): denies it`).
 */
export function itemWhere(item: PathItem): string {
  return item.where;
}

/** `10.1.10.5 → 10.0.1.5` */
export function traceEnds(query: PathTraceQuery): string {
  return `${query.source} → ${query.destination}`;
}

/**
 * Why a leg with a subnet or address at one end is not traced: the other end
 * was picked as a device or site. Null when the leg is traced or has no
 * subnet end.
 */
export function uncheckedTraceNote(from: PathPick, to: PathPick): string | null {
  // Both subnets: traced. Both devices: there is no address to trace.
  const devices = [from, to].filter((p) => !p.subnet);
  if (devices.length !== 1) return null;
  return (
    'Routes, policies and NAT are checked only between two subnets or IP addresses: ' +
    `add ${devices[0].label} with the subnet box instead (one of its subnets, or an IP address).`
  );
}
