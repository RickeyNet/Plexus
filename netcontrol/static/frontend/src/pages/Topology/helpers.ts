import type { TopologyData, TopologyEdge, TopologyNode } from '@/api/topology';
import { cloudProviderTerms } from '@/lib/cloudProviderTerms';

// ── Theme Colors ──────────────────────────────────────────────────────────

export interface TopoThemeColors {
  nodeFont: string;
  nodeFontStroke: string;
  edgeFont: string;
  edgeFontStroke: string;
  externalBg: string;
  externalBorder: string;
  externalHighlightBg: string;
  externalHighlightBorder: string;
  cisco: VendorColor;
  juniper: VendorColor;
  arista: VendorColor;
  fortinet: VendorColor;
  unknown: VendorColor;
  edgeCdp: EdgeColor;
  edgeLldp: EdgeColor;
  edgeOspf: EdgeColor;
  edgeBgp: EdgeColor;
  edgeInferred: EdgeColor;
  meraki: VendorColor;
  edgeVpn: EdgeColor;
  edgeWan: EdgeColor;
  edgeCloud: EdgeColor;
  pathGlow: string;
  dimColor: { background: string; border: string };
  dimEdge: EdgeColor;
}

export interface VendorColor {
  background: string;
  border: string;
  highlight: { background: string; border: string };
  hover: { background: string; border: string };
}

export interface EdgeColor {
  color: string;
  highlight: string;
  hover: string;
  opacity: number;
}

export function getTopoThemeColors(): TopoThemeColors {
  const style = getComputedStyle(document.documentElement);
  const theme = document.documentElement.getAttribute('data-theme') || 'forest';
  const isDark = !['light', 'sandstone'].includes(theme);
  const hasLightTopoNodes = ['light', 'sandstone'].includes(theme);
  const v = (prop: string, fallback: string) =>
    style.getPropertyValue(prop).trim() || fallback;
  return {
    nodeFont: hasLightTopoNodes ? '#2a1818' : v('--text', '#c8d4c8'),
    nodeFontStroke: hasLightTopoNodes ? 'rgba(255,255,255,0.7)' : 'rgba(0,0,0,0.6)',
    edgeFont: hasLightTopoNodes ? '#4a3030' : v('--text-muted', '#7a8a7a'),
    edgeFontStroke: hasLightTopoNodes ? 'rgba(255,255,255,0.6)' : 'rgba(0,0,0,0.5)',
    externalBg: isDark ? '#263238' : v('--bg-secondary', '#edf2ea'),
    externalBorder: isDark ? '#546e7a' : v('--border', '#d1d9d1'),
    externalHighlightBg: isDark ? '#37474f' : v('--card-bg-hover', '#f2f5ef'),
    externalHighlightBorder: isDark ? '#90a4ae' : v('--border-light', '#c1c9c1'),
    cisco: vendor(v, 'cisco', '#0d47a1', '#42a5f5', '#1565c0', '#90caf9'),
    juniper: vendor(v, 'juniper', '#1b5e20', '#66bb6a', '#2e7d32', '#a5d6a7'),
    arista: vendor(v, 'arista', '#e65100', '#ffa726', '#f57c00', '#ffcc80'),
    fortinet: vendor(v, 'fortinet', '#b71c1c', '#ef5350', '#c62828', '#ef9a9a'),
    unknown: vendor(v, 'unknown', '#37474f', '#78909c', '#455a64', '#b0bec5'),
    edgeCdp: edge(v, 'cdp', '#00b0ff', '#40c4ff', 0.8),
    edgeLldp: edge(v, 'lldp', '#00e676', '#69f0ae', 0.8),
    edgeOspf: edge(v, 'ospf', '#ffab40', '#ffd180', 0.8),
    edgeBgp: edge(v, 'bgp', '#e040fb', '#ea80fc', 0.8),
    edgeInferred: edge(v, 'inferred', '#9e9e9e', '#bdbdbd', 0.65),
    meraki: vendor(v, 'meraki', '#33691e', '#8bc34a', '#558b2f', '#c5e1a5'),
    edgeVpn: edge(v, 'vpn', '#ba68c8', '#ce93d8', 0.6),
    edgeWan: edge(v, 'wan', '#4fc3f7', '#81d4fa', 0.8),
    edgeCloud: edge(v, 'cloud', '#ff9800', '#ffb74d', 0.8),
    pathGlow: v('--topo-path-glow', 'rgba(255,255,255,0.6)'),
    dimColor: {
      background: v('--topo-dim-bg', 'rgba(40,50,60,0.4)'),
      border: v('--topo-dim-border', 'rgba(60,70,80,0.4)'),
    },
    dimEdge: {
      color: v('--topo-dim-edge', 'rgba(80,90,100,0.2)'),
      highlight: v('--topo-dim-edge-hi', 'rgba(80,90,100,0.3)'),
      hover: v('--topo-dim-edge-hi', 'rgba(80,90,100,0.3)'),
      opacity: 0.2,
    },
  };
}

function vendor(
  v: (k: string, f: string) => string,
  name: string,
  bg: string,
  border: string,
  hiBg: string,
  hiBorder: string,
): VendorColor {
  const colors = {
    background: v(`--topo-${name}-bg`, bg),
    border: v(`--topo-${name}-border`, border),
    highlight: {
      background: v(`--topo-${name}-hi-bg`, hiBg),
      border: v(`--topo-${name}-hi-border`, hiBorder),
    },
    hover: {
      background: v(`--topo-${name}-hi-bg`, hiBg),
      border: v(`--topo-${name}-hi-border`, hiBorder),
    },
  };
  return colors;
}

function edge(
  v: (k: string, f: string) => string,
  name: string,
  color: string,
  highlight: string,
  opacity: number,
): EdgeColor {
  return {
    color: v(`--topo-edge-${name}`, color),
    highlight: v(`--topo-edge-${name}-hi`, highlight),
    hover: v(`--topo-edge-${name}-hi`, highlight),
    opacity,
  };
}

// ── Icons & shapes ────────────────────────────────────────────────────────

const ICON_MAP: Record<string, string> = {
  router: '/static/img/topo/router.svg',
  switch: '/static/img/topo/switch.svg',
  firewall: '/static/img/topo/firewall.svg',
  wireless: '/static/img/topo/wireless.svg',
  wlc: '/static/img/topo/wlc.svg',
  phone: '/static/img/topo/phone.svg',
  // A remote user of a SASE cloud (a Cato Client).
  user: '/static/img/topo/user.svg',
  server: '/static/img/topo/server.svg',
  unknown: '/static/img/topo/unknown.svg',
};

const FIREWALL_DEVICE_TYPES = new Set([
  'fortinet',
  'paloalto_panos',
  'cisco_asa',
  'cisco_ftd',
]);

/** Devices Plexus has first-hand data for: inventory hosts and Meraki-managed devices. */
export function isManagedNode(node: TopologyNode): boolean {
  return node.in_inventory || node.source === 'meraki';
}

/** Display name of the integration a snapshot node came from. */
export function providerLabel(provider?: string | null): string {
  if (provider === 'aws') return 'AWS';
  if (provider === 'azure') return 'Azure';
  if (provider === 'gcp') return 'GCP';
  if (provider === 'fmc') return 'Cisco FMC';
  if (provider === 'panorama') return 'Palo Alto Panorama';
  return provider === 'cato' ? 'Cato' : 'Meraki';
}

/**
 * Cell padding for the tables in the device details panel. The shared
 * `.data-table` class sets no padding, so without this the columns run
 * together. Right padding only, so the first column stays flush left.
 */
export const DETAIL_CELL_STYLE = {
  padding: '0.3rem 1rem 0.3rem 0',
  verticalAlign: 'top',
} as const;

/** A table wider than the panel scrolls sideways; the scrollbar stays visible so the cut-off is obviously scrollable (overlay scrollbars hide it). */
export const SCROLL_X_STYLE = {
  overflowX: 'auto',
  scrollbarWidth: 'thin',
  scrollbarColor: 'var(--text-muted) transparent',
} as const;

export const DETAILS_PANEL_MIN_WIDTH = 380;

/** Width of the details panel while its left edge is dragged from startX to clientX; never narrower than the minimum nor wider than the map minus its margins. */
export function draggedPanelWidth(startWidth: number, startX: number, clientX: number, mapWidth: number): number {
  // The panel is pinned on the right, so dragging its left edge left widens it.
  const wanted = startWidth + (startX - clientX);
  // 0.75rem margin on each side of the panel inside the map.
  const max = Math.max(DETAILS_PANEL_MIN_WIDTH, mapWidth - 24);
  return Math.round(Math.min(max, Math.max(DETAILS_PANEL_MIN_WIDTH, wanted)));
}

/** Where the integration's data is read from. */
export function providerSourceName(provider?: string | null): string {
  if (provider === 'aws') return 'AWS API';
  if (provider === 'azure') return 'Azure API';
  if (provider === 'gcp') return 'GCP API';
  if (provider === 'fmc') return 'FMC API';
  if (provider === 'panorama') return 'Panorama API';
  return provider === 'cato' ? 'Cato API' : 'Meraki Dashboard';
}

/**
 * The link kind shown in the link and node panels. A `stack` link from a
 * Cisco FMC (or a Palo Alto Panorama) joins the members of a firewall HA
 * pair or cluster, not a switch
 * stack; the box its ends sit in (`ha:...` or `cluster:...`) tells which.
 */
export function edgeProtocolLabel(edge: TopologyEdge, a?: TopologyNode, b?: TopologyNode): string {
  if (edge.protocol === 'stack' && (edge.provider === 'fmc' || edge.provider === 'panorama')) {
    const sites = [a, b].map((n) => n?.meraki?.site_id ?? '');
    if (sites.some((s) => s.startsWith('cluster:'))) return 'CLUSTER';
    if (sites.some((s) => s.startsWith('ha:'))) return 'HA';
    return 'HA / CLUSTER';
  }
  return (edge.protocol ?? 'L2').toUpperCase();
}

/** What one entry of the integration is called. */
export function providerScopeName(provider?: string | null): string {
  if (provider === 'aws' || provider === 'azure' || provider === 'gcp') return cloudProviderTerms(provider).scopeTitle;
  if (provider === 'fmc') return 'Cisco FMC';
  if (provider === 'panorama') return 'Panorama';
  return provider === 'cato' ? 'Cato account' : 'Meraki organization';
}

/** WAN uplink stubs and non-Meraki VPN peers: endpoints, not devices. */
export function isMerakiEndpointNode(node: TopologyNode): boolean {
  return node.source === 'meraki' && ['wan', 'vpn_peer'].includes(node.meraki?.kind ?? '');
}

/** One remote user of a SASE cloud (a Cato Client): drawn small, hundreds at a time. */
export function isRemoteUserNode(node: TopologyNode): boolean {
  return node.source === 'meraki' && node.meraki?.kind === 'user';
}

export function nodeIconUrl(node: TopologyNode): string | undefined {
  const cat = (node.device_category || '').toLowerCase();
  if (cat && ICON_MAP[cat]) return ICON_MAP[cat];
  if (node.device_type && FIREWALL_DEVICE_TYPES.has(node.device_type)) return ICON_MAP.firewall;
  if (node.source === 'meraki') return undefined;
  if (!node.in_inventory) return ICON_MAP.unknown;
  return undefined;
}

export function merakiNodeShape(node: TopologyNode): string {
  const kind = node.meraki?.kind;
  if (kind === 'wan') return 'triangleDown';
  if (kind === 'vpn_peer') return 'hexagon';
  // A SASE cloud: its PoPs and backbone, and the remote-user group.
  if (kind === 'cloud') return 'hexagon';
  if (kind === 'users') return 'star';
  // A VPC's own router.
  if (kind === 'vpc') return 'diamond';
  return 'square';
}

const MERAKI_STATUS_BORDER: Record<string, string> = {
  offline: '#f44336',
  alerting: '#ffb300',
};

export function nodeShape(deviceType?: string | null): string {
  if (deviceType && FIREWALL_DEVICE_TYPES.has(deviceType)) return 'triangle';
  if (deviceType && ['cisco_ios', 'juniper_junos', 'arista_eos'].includes(deviceType)) {
    return 'diamond';
  }
  return 'dot';
}

export function nodeColor(node: TopologyNode, tc: TopoThemeColors): VendorColor {
  if (node.source === 'meraki') {
    // Meraki reports device health; surface a problem as the node border.
    const border = MERAKI_STATUS_BORDER[node.meraki?.status ?? ''];
    if (!border) return tc.meraki;
    return {
      ...tc.meraki,
      border,
      highlight: { ...tc.meraki.highlight, border },
      hover: { ...tc.meraki.hover, border },
    };
  }
  if (!node.in_inventory) {
    return {
      background: tc.externalBg,
      border: tc.externalBorder,
      highlight: { background: tc.externalHighlightBg, border: tc.externalHighlightBorder },
      hover: { background: tc.externalHighlightBg, border: tc.externalHighlightBorder },
    };
  }
  const map: Record<string, VendorColor> = {
    cisco_ios: tc.cisco,
    cisco_asa: tc.cisco,
    cisco_ftd: tc.cisco,
    juniper_junos: tc.juniper,
    arista_eos: tc.arista,
    fortinet: tc.fortinet,
  };
  return (node.device_type && map[node.device_type]) || tc.unknown;
}

export function edgeProtocolColor(protocol: string | null | undefined, tc: TopoThemeColors): EdgeColor {
  if (protocol === 'lldp') return tc.edgeLldp;
  if (protocol === 'ospf') return tc.edgeOspf;
  if (protocol === 'bgp') return tc.edgeBgp;
  if (protocol === 'inferred-fdb') return tc.edgeInferred;
  // A management relationship (FMC to FTD, Panorama to firewall): no traffic, drawn faintly.
  if (protocol === 'management') return tc.edgeInferred;
  if (protocol === 'vpn' || protocol === 'vpn-ipsec') return tc.edgeVpn;
  if (protocol === 'wan') return tc.edgeWan;
  if (protocol === 'cloud') return tc.edgeCloud;
  return tc.edgeCdp;
}

const DOWN_EDGE_STATUSES = new Set(['unreachable', 'failed']);

/** A Meraki VPN tunnel or WAN uplink that the Dashboard reports as down. */
export function isEdgeDown(edge: TopologyEdge): boolean {
  return DOWN_EDGE_STATUSES.has(String(edge.status ?? '').toLowerCase());
}

// ── Utilization color ramp ────────────────────────────────────────────────

export function utilColor(pct: number): EdgeColor {
  let r: number, g: number, b: number;
  if (pct <= 50) {
    const t = pct / 50;
    r = Math.round(76 + (255 - 76) * t);
    g = Math.round(175 + (235 - 175) * t);
    b = Math.round(80 + (59 - 80) * t);
  } else {
    const t = (pct - 50) / 50;
    r = Math.round(255 + (244 - 255) * t);
    g = Math.round(235 - 235 * t * 0.85);
    b = Math.round(59 + (67 - 59) * t);
  }
  const hex = `#${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}`;
  return { color: hex, highlight: hex, hover: hex, opacity: 0.9 };
}

export function utilShadow(pct: number): string {
  if (pct > 75) return 'rgba(244,67,54,0.4)';
  if (pct > 50) return 'rgba(255,235,59,0.3)';
  return 'rgba(76,175,80,0.3)';
}

export function formatBps(bps?: number | null): string {
  if (!bps || bps < 0) return '0 bps';
  if (bps >= 1e9) return (bps / 1e9).toFixed(1) + ' Gbps';
  if (bps >= 1e6) return (bps / 1e6).toFixed(1) + ' Mbps';
  if (bps >= 1e3) return (bps / 1e3).toFixed(1) + ' Kbps';
  return bps + ' bps';
}

// ── Interface name normalization & abbreviation ──────────────────────────

export function normalizeIfaceName(name?: string | null): string {
  let n = String(name || '').trim().toLowerCase();
  if (!n) return '';
  n = n.replace(/\s+/g, '');
  return n
    .replace(/tengigabitethernet/g, 'te')
    .replace(/gigabitethernet/g, 'gi')
    .replace(/fastethernet/g, 'fa')
    .replace(/port-channel/g, 'po')
    .replace(/ethernet/g, 'eth');
}

export function abbreviateInterface(name?: string | null): string {
  if (!name) return '';
  return name
    .replace(/TwentyFiveGigE(?:thernet)?/gi, '25G')
    .replace(/HundredGigE(?:thernet)?/gi, '100G')
    .replace(/FortyGigabitEthernet/gi, '40G')
    .replace(/TenGigabitEthernet/gi, 'Te')
    .replace(/TwoGigabitEthernet/gi, '2G')
    .replace(/FiveGigabitEthernet/gi, '5G')
    .replace(/GigabitEthernet/gi, 'Gi')
    .replace(/FastEthernet/gi, 'Fa')
    .replace(/Port-channel/gi, 'Po')
    .replace(/Loopback/gi, 'Lo')
    .replace(/Vlan/gi, 'Vl')
    .replace(/Ethernet/gi, 'Eth');
}

export function stpPortKey(hostId: number | string, iface?: string | null): string {
  return `${String(hostId)}|${normalizeIfaceName(iface)}`;
}

export interface StpStyle {
  color: EdgeColor;
  width: number;
  dashes: false | number[];
  shadow: string;
}

export function stpStyle(state?: string | null): StpStyle | null {
  const s = String(state || '').toLowerCase();
  if (s === 'forwarding') {
    return {
      color: { color: '#43a047', highlight: '#66bb6a', hover: '#66bb6a', opacity: 0.9 },
      width: 4,
      dashes: false,
      shadow: 'rgba(67,160,71,0.35)',
    };
  }
  if (s === 'learning' || s === 'listening') {
    return {
      color: { color: '#f9a825', highlight: '#fbc02d', hover: '#fbc02d', opacity: 0.95 },
      width: 4,
      dashes: [6, 4],
      shadow: 'rgba(249,168,37,0.35)',
    };
  }
  if (s === 'blocking' || s === 'discarding' || s === 'disabled' || s === 'broken') {
    return {
      color: { color: '#e53935', highlight: '#ef5350', hover: '#ef5350', opacity: 0.95 },
      width: 6,
      dashes: [4, 3],
      shadow: 'rgba(229,57,53,0.45)',
    };
  }
  return null;
}

// ── BFS shortest path ─────────────────────────────────────────────────────

export function bfsShortestPath(
  startId: number | string,
  endId: number | string,
  edges: TopologyEdge[],
): (number | string)[] | null {
  const adj = new Map<number | string, (number | string)[]>();
  for (const e of edges) {
    if (!adj.has(e.from)) adj.set(e.from, []);
    if (!adj.has(e.to)) adj.set(e.to, []);
    adj.get(e.from)!.push(e.to);
    adj.get(e.to)!.push(e.from);
  }
  const visited = new Set<number | string>([startId]);
  const queue: (number | string)[][] = [[startId]];
  while (queue.length) {
    const path = queue.shift()!;
    const cur = path[path.length - 1];
    if (cur === endId) return path;
    for (const nb of adj.get(cur) || []) {
      if (!visited.has(nb)) {
        visited.add(nb);
        queue.push([...path, nb]);
      }
    }
  }
  return null;
}

export function nodeTitle(node: TopologyNode): string {
  const modelInfo = node.model ? `\nModel: ${node.model}` : '';
  const categoryInfo = node.device_category ? `\nRole: ${node.device_category}` : '';
  const ipamSubnet = node.ipam_subnet || '';
  const hasPct = node.ipam_utilization_pct != null && !Number.isNaN(Number(node.ipam_utilization_pct));
  const ipamPct = hasPct ? `${Math.round(Number(node.ipam_utilization_pct))}%` : 'n/a';
  const ipamInfo = ipamSubnet ? `\nIPAM: ${ipamSubnet} (${ipamPct})` : '';
  const instance = node.instance;
  const instanceInfo = instance ? `\nInstance: ${instance.id}${instance.subnet ? ` · ${instance.subnet}` : ''}` : '';
  if (node.source === 'meraki') {
    const site = node.meraki?.site_name ? `\nSite: ${node.meraki.site_name}` : '';
    // An AWS node's site already is its VPC; another integration's names it here.
    const vpcInfo = instance?.vpc && node.meraki?.provider !== 'aws' ? `\nVPC: ${instance.vpc}` : '';
    return `${node.label}\n${node.ip || ''}\n${providerLabel(node.meraki?.provider)} ${node.meraki?.kind ?? 'device'} · ${node.meraki?.status ?? 'unknown'}${modelInfo}${site}${instanceInfo}${vpcInfo}\nDrag to move · Right-click to unpin`;
  }
  const vpcInfo = instance?.vpc ? `\nVPC: ${instance.vpc}` : '';
  return `${node.label}\n${node.ip || ''}\nType: ${node.device_type ?? ''}${categoryInfo}${modelInfo}${node.group_name ? '\nGroup: ' + node.group_name : ''}${node.in_inventory ? '' : '\n(External)'}${ipamInfo}${instanceInfo}${vpcInfo}\nDrag to move · Right-click to unpin`;
}

// ── Source filter ────────────────────────────────────────────────────────

/**
 * Which part of the map to show: everything, the inventory, every
 * integration, or one integration (`provider:aws`, `provider:cato`, ...).
 */
export type SourceFilter = 'all' | 'inventory' | 'meraki' | `provider:${string}`;

export const PROVIDER_ORDER = ['meraki', 'cato', 'fmc', 'panorama', 'aws', 'azure', 'gcp'];

/** The integration a node belongs to, or '' for an inventory-only node. */
export function nodeProvider(node: TopologyNode): string {
  return node.meraki ? node.meraki.provider || 'meraki' : '';
}

/** The integrations present on the map, in a stable order, for the filter menu. */
export function mapProviders(data: TopologyData | undefined): string[] {
  const found = new Set((data?.nodes ?? []).map(nodeProvider).filter(Boolean));
  const known = PROVIDER_ORDER.filter((p) => found.has(p));
  const others = [...found].filter((p) => !PROVIDER_ORDER.includes(p)).sort();
  return [...known, ...others];
}

const TUNNEL_PROTOCOLS = new Set(['vpn', 'vpn-ipsec']);

export function filterBySource(data: TopologyData | undefined, filter: SourceFilter): TopologyData | undefined {
  if (!data || filter === 'all') return data;
  const only = filter.startsWith('provider:') ? filter.slice('provider:'.length) : '';
  const keepNode = (n: TopologyNode): boolean => {
    if (only) return nodeProvider(n) === only || !!n.also_providers?.includes(only);
    return filter === 'meraki' ? !!n.meraki : n.source !== 'meraki';
  };
  const kept = new Set(data.nodes.filter(keepNode).map((n) => n.id));
  // A device another integration runs here (a Cato vSocket on an AWS
  // instance) keeps its tunnels into that integration's cloud (its PoP), so
  // one source still shows where its VPN goes.
  const guestEdges = new Set<TopologyEdge['id']>();
  if (only) {
    const byId = new Map(data.nodes.map((n) => [n.id, n]));
    const guest = (id: TopologyNode['id']) => kept.has(id) && nodeProvider(byId.get(id)!) !== only;
    const isCloud = (id: TopologyNode['id']) => byId.get(id)?.meraki?.kind === 'cloud';
    for (const e of data.edges) {
      if (!TUNNEL_PROTOCOLS.has(e.protocol ?? '')) continue;
      for (const [near, far] of [[e.from, e.to], [e.to, e.from]]) {
        if (guest(near) && isCloud(far)) guestEdges.add(e.id);
      }
    }
    for (const e of data.edges) {
      if (guestEdges.has(e.id)) kept.add(e.from).add(e.to);
    }
  }
  const nodes = data.nodes.filter((n) => kept.has(n.id));
  const edges = data.edges.filter((e) => {
    if (guestEdges.has(e.id)) return true;
    if (!kept.has(e.from) || !kept.has(e.to)) return false;
    if (only) return e.source !== 'meraki' || (e.provider || 'meraki') === only;
    return filter === 'meraki' || e.source !== 'meraki';
  });
  return { ...data, nodes, edges };
}

/** Text the toolbar search box matches locally, before the server-side deep search. */
export function nodeSearchText(node: TopologyNode): string {
  return [
    node.label,
    node.ip,
    node.model,
    node.group_name,
    node.device_type,
    node.meraki?.serial,
    node.meraki?.site_name,
    node.meraki?.instance_id,
    node.instance?.id,
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
}

export function merakiNodeKey(orgRef: number, nodeId: string): string {
  return `${orgRef}|${nodeId}`;
}
