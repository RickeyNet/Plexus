import type { AwsReachabilityQuery, MerakiSubnet } from '@/api/meraki';
import type { TopologyEdge, TopologyNode } from '@/api/topology';

import { isEdgeDown } from './helpers';
import { layoutGroupKey } from './layout';

// Path mode: how a set of picked devices / sites reach one another over the
// links on the map. This follows topology (cables, uplinks, VPN tunnels that
// are up), not route tables. Where a leg has an end in AWS, the server also
// checks the route tables, network ACLs and security groups (reachabilityQuery).

type NodeId = number | string;

/** Most endpoints a path can connect (every pair is traced). */
export const MAX_PATH_ENDPOINTS = 6;

// A non-Meraki IPsec tunnel is only taken when no AutoVPN/cabled way exists
// that is about as short.
const THIRD_PARTY_VPN_COST = 2;

export interface PathSite {
  key: string;
  name: string;
  /** The device that stands for the site: its appliance, else a switch. */
  gateway: NodeId;
}

export interface PathLeg {
  from: NodeId;
  to: NodeId;
  /** Devices from `from` to `to`, both included; null when unreachable. */
  path: NodeId[] | null;
  /** Protocol of the link taken into each device after the first. */
  via: string[];
}

/** Something picked for the path: a device, a site's gateway or a subnet's owner. */
export interface PathPick {
  key: string;
  node: NodeId;
  label: string;
  subnet?: MerakiSubnet;
  /** The address typed to pick `subnet`, when it is narrower than the subnet. */
  address?: string;
}

export interface PickLeg {
  from: PathPick;
  to: PathPick;
  path: NodeId[] | null;
  /** Both picks live on the same device (two VLANs of one appliance). */
  sameDevice: boolean;
  /** Reasons the drawn path may not carry the picked subnets. */
  notes: string[];
}

export interface PickResult {
  legs: PickLeg[];
  nodeIds: Set<NodeId>;
  edgeIds: Set<NodeId>;
}

export interface PathResult {
  legs: PathLeg[];
  nodeIds: Set<NodeId>;
  edgeIds: Set<NodeId>;
}

// A VPC's own router stands for the VPC even when it holds an appliance.
const GATEWAY_ORDER = ['vpc', 'appliance', 'switch', 'wireless'];
// Stubs, neighbors, VPN peers and the nodes of a SASE cloud stand for no site.
const NOT_A_SITE_DEVICE = new Set(['wan', 'external', 'vpn_peer', 'cloud', 'users']);

/** Meraki sites that can be picked as a path endpoint, by name. */
export function pathSites(nodes: TopologyNode[]): PathSite[] {
  const best = new Map<string, { site: PathSite; rank: number }>();
  for (const node of nodes) {
    const ref = node.meraki;
    if (!ref?.site_id || NOT_A_SITE_DEVICE.has(ref.kind)) continue;
    const order = GATEWAY_ORDER.indexOf(ref.kind);
    const rank = order === -1 ? GATEWAY_ORDER.length : order;
    const key = layoutGroupKey(node);
    const seen = best.get(key);
    if (!seen || rank < seen.rank) {
      best.set(key, { site: { key, name: ref.site_name || ref.site_id, gateway: node.id }, rank });
    }
  }
  return [...best.values()]
    .map((entry) => entry.site)
    .sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' }));
}

function edgeCost(edge: TopologyEdge): number {
  return edge.protocol === 'vpn-ipsec' ? THIRD_PARTY_VPN_COST : 1;
}

/** Trace every pair of `endpoints` over the links that are up. */
export function connectEndpoints(endpoints: NodeId[], edges: TopologyEdge[]): PathResult {
  const result: PathResult = { legs: [], nodeIds: new Set(endpoints), edgeIds: new Set() };
  if (endpoints.length < 2) return result;

  const adjacency = new Map<NodeId, { to: NodeId; cost: number }[]>();
  const link = (a: NodeId, b: NodeId, cost: number) => {
    const list = adjacency.get(a);
    if (list) list.push({ to: b, cost });
    else adjacency.set(a, [{ to: b, cost }]);
  };
  // Every live link between a device pair, and the protocol of the cheapest.
  const between = new Map<string, NodeId[]>();
  const cheapest = new Map<string, { cost: number; protocol: string }>();
  const pairKey = (a: NodeId, b: NodeId) => (String(a) < String(b) ? `${a}|${b}` : `${b}|${a}`);
  for (const edge of edges) {
    if (edge.from === edge.to || isEdgeDown(edge)) continue;
    const cost = edgeCost(edge);
    link(edge.from, edge.to, cost);
    link(edge.to, edge.from, cost);
    const key = pairKey(edge.from, edge.to);
    const ids = between.get(key);
    if (ids) ids.push(edge.id);
    else between.set(key, [edge.id]);
    if (cost < (cheapest.get(key)?.cost ?? Infinity)) cheapest.set(key, { cost, protocol: edge.protocol ?? '' });
  }

  // Costs are 1 or 2, so a bucket per distance is a full priority queue.
  const shortestFrom = (source: NodeId): Map<NodeId, NodeId | null> => {
    const parent = new Map<NodeId, NodeId | null>();
    const dist = new Map<NodeId, number>([[source, 0]]);
    const buckets: [NodeId, NodeId | null][][] = [[[source, null]]];
    for (let d = 0; d < buckets.length; d++) {
      for (const [id, via] of buckets[d] ?? []) {
        if (parent.has(id) || dist.get(id) !== d) continue;
        parent.set(id, via);
        for (const next of adjacency.get(id) ?? []) {
          const nd = d + next.cost;
          if (parent.has(next.to) || (dist.get(next.to) ?? Infinity) <= nd) continue;
          dist.set(next.to, nd);
          (buckets[nd] ??= []).push([next.to, id]);
        }
      }
    }
    return parent;
  };

  for (let i = 0; i < endpoints.length - 1; i++) {
    const parent = shortestFrom(endpoints[i]);
    for (let j = i + 1; j < endpoints.length; j++) {
      const target = endpoints[j];
      if (!parent.has(target)) {
        result.legs.push({ from: endpoints[i], to: target, path: null, via: [] });
        continue;
      }
      const path: NodeId[] = [];
      for (let at: NodeId | null = target; at !== null; at = parent.get(at) ?? null) path.push(at);
      path.reverse();
      const via = path.slice(1).map((id, idx) => cheapest.get(pairKey(path[idx], id))?.protocol ?? '');
      result.legs.push({ from: endpoints[i], to: target, path, via });
      path.forEach((id, idx) => {
        result.nodeIds.add(id);
        if (idx > 0) for (const edgeId of between.get(pairKey(path[idx - 1], id)) ?? []) result.edgeIds.add(edgeId);
      });
    }
  }
  return result;
}

const TUNNEL_PROTOCOLS = new Set(['vpn', 'vpn-ipsec']);

function subnetNotes(pick: PathPick, tunnels: number): string[] {
  const subnet = pick.subnet;
  if (!subnet || !tunnels) return [];
  if (subnet.kind === 'peer') {
    return tunnels > 1
      ? [`${subnet.cidr} is behind a non-Meraki VPN peer: only a site with its own tunnel to that peer reaches it, the route is not passed on over AutoVPN.`]
      : [];
  }
  return subnet.in_vpn === false
    ? [`${subnet.cidr} is not advertised into the VPN at ${subnet.site_name || 'its site'}, so a tunnel will not carry it.`]
    : [];
}

/** Trace every pair of picks; two picks on one device need no path. */
export function connectPicks(picks: PathPick[], edges: TopologyEdge[]): PickResult {
  const traced = connectEndpoints([...new Set(picks.map((p) => p.node))], edges);
  const legs: PickLeg[] = [];
  for (let i = 0; i < picks.length - 1; i++) {
    for (let j = i + 1; j < picks.length; j++) {
      const from = picks[i];
      const to = picks[j];
      if (from.node === to.node) {
        legs.push({ from, to, path: [from.node], sameDevice: true, notes: [] });
        continue;
      }
      const forward = traced.legs.find((l) => l.from === from.node && l.to === to.node);
      const back = forward ? undefined : traced.legs.find((l) => l.from === to.node && l.to === from.node);
      const leg = forward ?? back;
      const path = leg?.path ? (forward ? leg.path : [...leg.path].reverse()) : null;
      const tunnels = (leg?.via ?? []).filter((p) => TUNNEL_PROTOCOLS.has(p)).length;
      legs.push({ from, to, path, sameDevice: false, notes: [...subnetNotes(from, tunnels), ...subnetNotes(to, tunnels)] });
    }
  }
  return { legs, nodeIds: traced.nodeIds, edgeIds: traced.edgeIds };
}

export interface TrafficFilter {
  /** tcp / udp / icmp; empty for any traffic. */
  protocol: string;
  port?: number;
}

/**
 * Traffic typed as `tcp/443`, `udp 53`, `443` (TCP), `icmp` or nothing (any
 * traffic). Null when the text is none of these.
 */
export function parseTraffic(text: string): TrafficFilter | null {
  const wanted = text.trim().toLowerCase();
  if (!wanted || wanted === 'any' || wanted === 'all') return { protocol: '' };
  const match = /^(?:(tcp|udp|icmp)(?:\s*[/:\s]\s*(\d{1,5}))?|(\d{1,5}))$/.exec(wanted);
  if (!match) return null;
  const protocol = match[1] ?? 'tcp';
  const digits = match[2] ?? match[3];
  if (digits === undefined) return { protocol };
  const port = Number(digits);
  return protocol === 'icmp' || port > 65535 ? null : { protocol, port };
}

/**
 * The check AWS can make for a leg: both ends are subnets or addresses and
 * at least one is in a VPC. Null when there is nothing for AWS to check.
 */
export function reachabilityQuery(from: PathPick, to: PathPick, traffic: TrafficFilter): AwsReachabilityQuery | null {
  if (!from.subnet || !to.subnet) return null;
  const inAws = (pick: PathPick) => pick.subnet?.provider === 'aws';
  if (!inAws(from) && !inAws(to)) return null;
  return {
    source: from.address ?? from.subnet.cidr,
    destination: to.address ?? to.subnet.cidr,
    // An AWS subnet's site is its VPC.
    source_vpc: inAws(from) ? from.subnet.site_id : undefined,
    destination_vpc: inAws(to) ? to.subnet.site_id : undefined,
    protocol: traffic.protocol,
    port: traffic.port,
  };
}

/** Text of a subnet in the picker; unique per (subnet, owner). */
export function subnetOptionLabel(subnet: MerakiSubnet): string {
  return `${subnet.cidr} - ${subnet.site_name || 'VPN peer'} - ${subnet.name}`;
}

function parseV4(text: string): { addr: number; len: number } | null {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(text.trim());
  if (!match) return null;
  const octets = match.slice(1, 5).map(Number);
  const len = match[5] === undefined ? 32 : Number(match[5]);
  if (octets.some((o) => o > 255) || len > 32) return null;
  return { addr: ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0, len };
}

/** Whether `text` is an IPv4 address or network rather than a name. */
export function isAddressText(text: string): boolean {
  return parseV4(text) !== null;
}

function prefix(addr: number, len: number): number {
  return len === 0 ? 0 : addr >>> (32 - len);
}

/**
 * Subnets `text` stands for: the picker entry it spells out, else the most
 * specific subnets containing the typed IPv4 address or network (several when
 * sites overlap).
 */
export function findSubnets(text: string, subnets: MerakiSubnet[]): MerakiSubnet[] {
  const wanted = text.trim();
  if (!wanted) return [];
  const exact = subnets.find((s) => subnetOptionLabel(s) === wanted);
  if (exact) return [exact];
  const query = parseV4(wanted);
  if (!query) return [];
  let best = -1;
  let found: MerakiSubnet[] = [];
  for (const subnet of subnets) {
    const net = parseV4(subnet.cidr);
    if (!net || net.len > query.len || prefix(net.addr, net.len) !== prefix(query.addr, net.len)) continue;
    if (net.len > best) {
      best = net.len;
      found = [subnet];
    } else if (net.len === best) {
      found.push(subnet);
    }
  }
  return found;
}
