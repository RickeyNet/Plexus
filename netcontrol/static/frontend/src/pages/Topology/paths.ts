import type { MerakiSubnet, PathAppSuggestion } from '@/api/meraki';
import type { TopologyEdge, TopologyNode } from '@/api/topology';

import { isEdgeDown, isRemoteUserNode, PROVIDER_INVENTORY } from './helpers';
import { layoutGroupKey } from './layout';
import { searchHost } from './merakiHelpers';

// Path mode: how a set of picked devices / sites reach one another over the
// links on the map. The path drawn follows topology (cables, uplinks, VPN
// tunnels that are up), not route tables. A leg between two subnets or
// addresses is also traced by the server hop by hop through each device's
// routes, policies and NAT (pathTrace.ts).

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
  /** Every live link between consecutive devices of `path`. */
  edgeIds: NodeId[];
}

/**
 * Something picked for the path: a device, a site's gateway, a subnet's owner,
 * or an internet application or domain (`app`), which is not on the map.
 */
export interface PathPick {
  key: string;
  /** The map device that stands for the pick; absent for an internet application. */
  node?: NodeId;
  label: string;
  subnet?: MerakiSubnet;
  /** The address typed to pick `subnet`, when it is narrower than the subnet. */
  address?: string;
  /**
   * An internet application or domain (`YouTube`, `youtube.com`), traced as
   * the destination of its legs whichever order it was picked in.
   */
  app?: string;
}

/** The address of a host entry of the index (`192.0.2.10/32` -> `192.0.2.10`); a wider network as it is. */
export function hostAddress(subnet: Pick<MerakiSubnet, 'cidr'>): string {
  return subnet.cidr.replace(/\/32$/, '');
}

/**
 * The pick a click on a remote user (a Cato or Appgate client) makes: the
 * user's own address, so the leg is traced hop by hop like a typed address,
 * since a user has exactly one. The same pick as typing the address, so the
 * two ways meet in one entry. Null for any other node, and for a user whose
 * address is not in `subnets` (a snapshot collected before the index had it).
 */
export function userPick(node: TopologyNode, subnets: MerakiSubnet[]): PathPick | null {
  const ref = node.meraki;
  if (!ref || !isRemoteUserNode(node)) return null;
  const subnet = subnets.find((s) => s.kind === 'user' && s.org_ref === ref.org_ref && s.node_id === ref.node_id);
  if (!subnet) return null;
  const address = hostAddress(subnet);
  const site = subnet.site_name || ref.site_name || '';
  return {
    key: `s:${subnet.org_ref}:${address}:${subnet.node_id}`,
    node: node.id,
    label: `${node.label || address} (${address})${site ? ` · ${site}` : ''}`,
    subnet,
    address,
  };
}

/**
 * The pick of `subnet` at its owner `node` for the text typed to find it: the
 * typed address is kept when it is narrower than the subnet, so the trace
 * matches rules against that address rather than the whole subnet.
 */
export function subnetPick(subnet: MerakiSubnet, node: NodeId, typed: string): PathPick {
  const text = typed.trim();
  const address = isAddressText(text) && text !== subnet.cidr ? text : undefined;
  return {
    key: `s:${subnet.org_ref}:${address ?? subnet.cidr}:${subnet.node_id}`,
    node,
    label: `${address ?? subnet.cidr} · ${subnet.site_name || subnet.name}`,
    subnet,
    address,
  };
}

export interface PickLeg {
  from: PathPick;
  to: PathPick;
  path: NodeId[] | null;
  /** Both picks live on the same device (two VLANs of one appliance). */
  sameDevice: boolean;
  /** Reasons the drawn path may not carry the picked subnets. */
  notes: string[];
  /** Links the drawn path runs over. */
  edgeIds: NodeId[];
  /** One end is an internet application: the leg leaves the map, so no path is drawn for it. */
  internet: boolean;
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
const NOT_A_SITE_DEVICE = new Set(['wan', 'external', 'vpn_peer', 'cloud', 'users', 'user']);

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

// A management relationship (an FMC and the FTDs it manages, a Panorama and
// its firewalls) carries no traffic: two headends are not joined through
// their manager.
const NO_TRAFFIC_PROTOCOLS = new Set(['management']);

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
    if (edge.from === edge.to || isEdgeDown(edge) || NO_TRAFFIC_PROTOCOLS.has(edge.protocol ?? '')) continue;
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
        result.legs.push({ from: endpoints[i], to: target, path: null, via: [], edgeIds: [] });
        continue;
      }
      const path: NodeId[] = [];
      for (let at: NodeId | null = target; at !== null; at = parent.get(at) ?? null) path.push(at);
      path.reverse();
      const via = path.slice(1).map((id, idx) => cheapest.get(pairKey(path[idx], id))?.protocol ?? '');
      const edgeIds = path.slice(1).flatMap((id, idx) => between.get(pairKey(path[idx], id)) ?? []);
      result.legs.push({ from: endpoints[i], to: target, path, via, edgeIds });
      for (const id of path) result.nodeIds.add(id);
      for (const edgeId of edgeIds) result.edgeIds.add(edgeId);
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

/** The map devices of `picks`, once each; an internet application has none. */
export function pickNodes(picks: PathPick[]): NodeId[] {
  return [...new Set(picks.flatMap((p) => (p.node === undefined ? [] : [p.node])))];
}

/**
 * Trace every pair of picks; two picks on one device need no path, and a leg
 * to an internet application has none on the map (only its trace).
 */
export function connectPicks(picks: PathPick[], edges: TopologyEdge[]): PickResult {
  const traced = connectEndpoints(pickNodes(picks), edges);
  const legs: PickLeg[] = [];
  for (let i = 0; i < picks.length - 1; i++) {
    for (let j = i + 1; j < picks.length; j++) {
      const from = picks[i];
      const to = picks[j];
      if (from.node === undefined || to.node === undefined) {
        legs.push({ from, to, path: null, sameDevice: false, notes: [], edgeIds: [], internet: true });
        continue;
      }
      if (from.node === to.node) {
        legs.push({ from, to, path: [from.node], sameDevice: true, notes: [], edgeIds: [], internet: false });
        continue;
      }
      const forward = traced.legs.find((l) => l.from === from.node && l.to === to.node);
      const back = forward ? undefined : traced.legs.find((l) => l.from === to.node && l.to === from.node);
      const leg = forward ?? back;
      const path = leg?.path ? (forward ? leg.path : [...leg.path].reverse()) : null;
      const tunnels = (leg?.via ?? []).filter((p) => TUNNEL_PROTOCOLS.has(p)).length;
      legs.push({
        from,
        to,
        path,
        sameDevice: false,
        notes: [...subnetNotes(from, tunnels), ...subnetNotes(to, tunnels)],
        edgeIds: leg?.edgeIds ?? [],
        internet: false,
      });
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

/** Text of a subnet in the picker; unique per (subnet, owner). */
export function subnetOptionLabel(subnet: MerakiSubnet): string {
  // A subnet with no site is behind a VPN peer, or on an inventory host with no group.
  const site = subnet.site_name || (subnet.provider === PROVIDER_INVENTORY ? 'Inventory' : 'VPN peer');
  return `${subnet.cidr} - ${site} - ${subnet.name}`;
}

/** The Path Mode prompt, naming the site and subnet inputs that are shown. */
export function pathModeHint(hasSites: boolean, hasSubnets: boolean): string {
  const extra = hasSites && hasSubnets
    ? 'sites, subnets and internet applications'
    : hasSites
      ? 'sites'
      : hasSubnets
        ? 'subnets, IP addresses or internet applications'
        : '';
  return `Click two or more devices on the map${extra ? `, or add ${extra},` : ''} to see how they reach one another.`;
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

/** A host offered for the name being typed, with the DNS name of its that matched (empty: its own name did). */
export interface HostSuggestion {
  host: MerakiSubnet;
  dnsName: string;
}

/** Most hosts offered under a subnet box. */
export const MAX_HOST_SUGGESTIONS = 12;

/**
 * The hosts to offer while a name is typed in a subnet box: those with a DNS
 * name or a resource name that holds the text (the host of a pasted URL, UNC
 * path, NFS mount or `host:port`), one per address. A name that starts with
 * the text comes before one that only holds it. None for fewer than two
 * characters, for an address being typed, or for a picker entry spelled out.
 */
export function suggestHosts(text: string, subnets: MerakiSubnet[], limit = MAX_HOST_SUGGESTIONS): HostSuggestion[] {
  const typed = text.trim();
  const wanted = searchHost(typed.toLowerCase()).replace(/\.$/, '');
  if (wanted.length < 2 || /^[\d./]+$/.test(wanted)) return [];
  const first: HostSuggestion[] = [];
  const rest: HostSuggestion[] = [];
  for (const host of subnets) {
    if (host.kind !== 'host') continue;
    if (subnetOptionLabel(host) === typed) return [];
    const names = host.dns_names ?? [];
    const dnsName = names.find((n) => n.startsWith(wanted)) ?? names.find((n) => n.includes(wanted));
    const own = host.name.toLowerCase();
    if (dnsName === undefined && !own.includes(wanted)) continue;
    const starts = dnsName?.startsWith(wanted) || own.startsWith(wanted);
    (starts ? first : rest).push({ host, dnsName: dnsName ?? names[0] ?? '' });
  }
  return [...first, ...rest].slice(0, limit);
}

/**
 * The hosts that answer to the DNS name `text` spells out, one per address
 * (an FSx file system or a service endpoint has several). A pasted URL, UNC
 * path, NFS mount or `host:port` stands for its host, as in the map search.
 */
export function findNamedHosts(text: string, subnets: MerakiSubnet[]): MerakiSubnet[] {
  const wanted = searchHost(text.trim().toLowerCase()).replace(/\.$/, '');
  if (!wanted || isAddressText(wanted)) return [];
  return subnets.filter((s) => s.dns_names?.includes(wanted));
}

/** What a pick stands for at the end of a leg: its address, subnet or internet application, else its name. */
export function pickEnd(pick: PathPick): string {
  return pick.address ?? pick.subnet?.cidr ?? pick.app ?? pick.label;
}

/** Longest application name or domain the trace takes. */
export const MAX_APP_LENGTH = 128;

/**
 * The internet application or domain `text` can be traced to as a
 * destination, or null when it is something the map knows: an IPv4 or IPv6
 * address or network (or part of one being typed), text the subnet picker
 * has entries for, an address inside a collected subnet, or the DNS name of
 * a collected host. A
 * pasted URL stands for its host (`https://www.example.com/a` ->
 * `www.example.com`). Hosts whose names only hold the text are offered first
 * by `suggestHosts`, but do not stop the text being taken as an application.
 */
export function appCandidate(text: string, subnets: MerakiSubnet[]): string | null {
  const typed = text.trim();
  const name = searchHost(typed).replace(/\.$/, '');
  if (name.length < 2 || name.length > MAX_APP_LENGTH) return null;
  // IPv4 being typed (`192.0`), or IPv6 (`2001:db8::1`, `::1`).
  if (/^[\d./]+$/.test(name) || /^[\da-f]*:[\da-f:.]*(?:\/\d{1,3})?$/i.test(name)) return null;
  // A picker entry, or text the subnet list offers entries for (it matches
  // anywhere in an entry, `Branch` finds the subnets of a site).
  const lower = typed.toLowerCase();
  if (subnets.some((s) => subnetOptionLabel(s).toLowerCase().includes(lower))) return null;
  if (findSubnets(typed, subnets).length || findNamedHosts(typed, subnets).length) return null;
  return name;
}

/** The pick of the internet application or domain `name` (from `appCandidate` or the server's list). */
export function appPick(name: string): PathPick {
  const app = name.trim();
  return { key: `a:${app.toLowerCase()}`, label: `Internet application: ${app}`, app };
}

/** An internet application or domain offered under the subnet box. */
export interface AppOption {
  /** What is traced to (`destination_app`). */
  name: string;
  title: string;
  detail: string;
}

const APP_KINDS: Record<PathAppSuggestion['kind'], string> = {
  application: 'Internet application',
  category: 'Application category',
  domain: 'Domain',
};

/**
 * The internet destinations offered for the typed `candidate` (see
 * `appCandidate`): the server's applications and domains, then always the typed text itself,
 * so it can be traced even when the server knows no such name. None without
 * a candidate.
 */
export function appOptions(candidate: string | null, suggestions: PathAppSuggestion[]): AppOption[] {
  if (!candidate) return [];
  const seen = new Set<string>();
  const found: AppOption[] = [];
  for (const item of suggestions) {
    const name = item.name.trim();
    // A category is not something a flow goes to: only a rule can name one.
    if (item.kind === 'category' || !name || seen.has(name.toLowerCase())) continue;
    seen.add(name.toLowerCase());
    found.push({ name, title: name, detail: [APP_KINDS[item.kind] ?? item.kind, item.source].filter(Boolean).join(' · ') });
  }
  return [
    ...found,
    {
      name: candidate,
      title: `Internet application or domain: ${candidate}`,
      detail: 'Traced to the internet as the destination of its legs',
    },
  ];
}
