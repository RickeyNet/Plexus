import type { TopologyEdge, TopologyNode } from '@/api/topology';

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
  server: '/static/img/topo/server.svg',
  unknown: '/static/img/topo/unknown.svg',
};

export function nodeIconUrl(node: TopologyNode): string | undefined {
  const cat = (node.device_category || '').toLowerCase();
  if (cat && ICON_MAP[cat]) return ICON_MAP[cat];
  if (node.device_type === 'fortinet') return ICON_MAP.firewall;
  if (!node.in_inventory) return ICON_MAP.unknown;
  return undefined;
}

export function nodeShape(deviceType?: string | null): string {
  if (deviceType === 'fortinet') return 'triangle';
  if (deviceType && ['cisco_ios', 'juniper_junos', 'arista_eos'].includes(deviceType)) {
    return 'diamond';
  }
  return 'dot';
}

export function nodeColor(node: TopologyNode, tc: TopoThemeColors): VendorColor {
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
  return tc.edgeCdp;
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
  return `${node.label}\n${node.ip || ''}\nType: ${node.device_type ?? ''}${categoryInfo}${modelInfo}${node.group_name ? '\nGroup: ' + node.group_name : ''}${node.in_inventory ? '' : '\n(External)'}${ipamInfo}\nDrag to move · Right-click to unpin`;
}
