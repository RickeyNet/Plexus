import type { TopologyEdge, TopologyNode } from '@/api/topology';

// Tidy left-to-right tree layout: the default arrangement of the map.
//
// Every connected part of the network becomes a tree that grows to the right
// from its most central gateway. Each node owns a horizontal band exactly as
// tall as its subtree, so no two nodes (or their labels) can overlap, and the
// result is deterministic - the same data always opens the same way.
//
// A small map stacks its trees. A large one (hundreds of sites hanging off a
// VPN hub) would become one unusably tall strip, so there every site is laid
// out as its own small tree and the sites are arranged in columns.

type NodeId = number | string;

export interface XY {
  x: number;
  y: number;
}

/** Labels longer than this are shortened on the map (the tooltip keeps the full name). */
export const TIDY_LABEL_MAX = 44;

const LABEL_CHAR_PX = 6.6;
const MIN_LEVEL_SEP = 240;
const DEVICE_ROW_H = 84;
const NEIGHBOR_ROW_H = 64;
const ENDPOINT_ROW_H = 48;
const GROUP_GAP = 56;
const COMPONENT_GAP = 120;
const MAX_LOOSE_COLS = 8;
// Trees stacked taller than this are split into blocks and flowed into columns.
const PACK_MIN_HEIGHT = 6000;
const PACK_GAP_Y = 110;
// Width : height the packed map aims for.
const PACK_ASPECT = 1.7;

// Logical adjacencies ride on top of the physical network; the tree follows
// cables first and only uses these to reach parts nothing else connects.
const OVERLAY_PROTOCOLS = new Set(['vpn', 'vpn-ipsec', 'ospf', 'bgp']);

const GATEWAY_TYPES = new Set(['fortinet', 'paloalto_panos', 'cisco_asa', 'cisco_ftd']);

export function tidyLabel(label: string): string {
  return label.length > TIDY_LABEL_MAX ? `${label.slice(0, TIDY_LABEL_MAX - 1)}…` : label;
}

/** Site (Meraki network) or inventory group a node is drawn with. */
export function layoutGroupKey(node: TopologyNode): string {
  if (node.meraki?.site_id) return `m:${node.meraki.org_ref}:${node.meraki.site_id}`;
  return node.group_name ? `g:${node.group_name}` : '';
}

// Lower ranks sit closer to the root: gateways, then switching, then the rest.
function tierRank(node: TopologyNode): number {
  const kind = node.meraki?.kind ?? '';
  const category = (node.device_category ?? '').toLowerCase();
  if (kind === 'wan' || kind === 'vpn_peer') return 5;
  if (kind === 'appliance' || category === 'firewall' || category === 'router') return 0;
  if (node.device_type && GATEWAY_TYPES.has(node.device_type)) return 0;
  if (kind === 'switch' || category === 'switch') return 1;
  if (kind === 'external' || (!node.in_inventory && node.source !== 'meraki')) return 4;
  if (kind === 'wireless' || category === 'wireless' || category === 'phone') return 3;
  return 2;
}

function rowHeight(node: TopologyNode): number {
  const kind = node.meraki?.kind ?? '';
  if (node.source === 'meraki' && (kind === 'wan' || kind === 'vpn_peer')) return ENDPOINT_ROW_H;
  return node.in_inventory || node.source === 'meraki' ? DEVICE_ROW_H : NEIGHBOR_ROW_H;
}

function compareLabels(a: TopologyNode, b: TopologyNode): number {
  return (
    a.label.localeCompare(b.label, undefined, { numeric: true, sensitivity: 'base' }) ||
    String(a.id).localeCompare(String(b.id))
  );
}

interface Block {
  root: NodeId;
  /** Positions relative to the block's top-left node column. */
  local: Map<NodeId, XY>;
  width: number;
  height: number;
}

export function tidyTreeLayout(nodes: TopologyNode[], edges: TopologyEdge[]): Map<NodeId, XY> {
  const positions = new Map<NodeId, XY>();
  if (!nodes.length) return positions;

  const byId = new Map<NodeId, TopologyNode>();
  for (const n of nodes) byId.set(n.id, n);

  // neighbor -> true when the only links between the pair are overlay links.
  const adjacency = new Map<NodeId, Map<NodeId, boolean>>();
  for (const n of nodes) adjacency.set(n.id, new Map());
  for (const e of edges) {
    if (e.from === e.to || !byId.has(e.from) || !byId.has(e.to)) continue;
    const overlay = OVERLAY_PROTOCOLS.has(e.protocol ?? '');
    const forward = adjacency.get(e.from)!;
    const backward = adjacency.get(e.to)!;
    forward.set(e.to, (forward.get(e.to) ?? true) && overlay);
    backward.set(e.from, (backward.get(e.from) ?? true) && overlay);
  }

  const group = new Map<NodeId, string>();
  const rank = new Map<NodeId, number>();
  for (const n of nodes) {
    group.set(n.id, layoutGroupKey(n));
    rank.set(n.id, tierRank(n));
  }

  const rootOrder = [...nodes].sort(
    (a, b) =>
      rank.get(a.id)! - rank.get(b.id)! ||
      adjacency.get(b.id)!.size - adjacency.get(a.id)!.size ||
      compareLabels(a, b),
  );

  let longestLabel = 0;
  for (const n of nodes) longestLabel = Math.max(longestLabel, n.label.length);
  const levelSep = Math.max(
    MIN_LEVEL_SEP,
    Math.round(Math.min(TIDY_LABEL_MAX, longestLabel) * LABEL_CHAR_PX + 40),
  );

  const visited = new Set<NodeId>();
  const children = new Map<NodeId, NodeId[]>();
  // Nodes whose only way into the tree was an overlay link (a VPN tunnel).
  const viaOverlay: NodeId[] = [];
  const roots: NodeId[] = [];
  const loose: TopologyNode[] = [];

  for (const root of rootOrder) {
    if (visited.has(root.id)) continue;
    visited.add(root.id);
    if (!adjacency.get(root.id)!.size) {
      loose.push(root);
      continue;
    }
    roots.push(root.id);

    // Breadth-first over physical links; an overlay link is only followed
    // once no physical link is left to try.
    const order: NodeId[] = [];
    const queue: NodeId[] = [root.id];
    const overlayQueue: [NodeId, NodeId][] = [];
    let head = 0;
    let overlayHead = 0;
    const adopt = (parent: NodeId, child: NodeId) => {
      visited.add(child);
      children.get(parent)!.push(child);
      queue.push(child);
    };
    for (;;) {
      if (head < queue.length) {
        const id = queue[head++];
        order.push(id);
        children.set(id, []);
        for (const [neighbor, overlay] of adjacency.get(id)!) {
          if (visited.has(neighbor)) continue;
          if (overlay) overlayQueue.push([id, neighbor]);
          else adopt(id, neighbor);
        }
      } else if (overlayHead < overlayQueue.length) {
        const [parent, child] = overlayQueue[overlayHead++];
        if (!visited.has(child)) {
          adopt(parent, child);
          viaOverlay.push(child);
        }
      } else {
        break;
      }
    }

    // Siblings: the parent's own site first, then site by site.
    for (const id of order) {
      const own = group.get(id)!;
      children.get(id)!.sort((a, b) => {
        const ga = group.get(a)!;
        const gb = group.get(b)!;
        if (ga !== gb) {
          if (ga === own) return -1;
          if (gb === own) return 1;
          return ga.localeCompare(gb);
        }
        return rank.get(a)! - rank.get(b)! || compareLabels(byId.get(a)!, byId.get(b)!);
      });
    }
  }

  const gapBefore = (siblings: NodeId[], idx: number) =>
    idx > 0 && group.get(siblings[idx])! !== group.get(siblings[idx - 1])! ? GROUP_GAP : 0;

  // Lay one tree out on its own, growing right from `root`.
  const placeBlock = (root: NodeId, kidsOf: (id: NodeId) => NodeId[]): Block => {
    const order: NodeId[] = [root];
    const depth = new Map<NodeId, number>([[root, 0]]);
    for (let i = 0; i < order.length; i++) {
      for (const kid of kidsOf(order[i])) {
        depth.set(kid, depth.get(order[i])! + 1);
        order.push(kid);
      }
    }

    // Band height of every subtree, leaves first.
    const band = new Map<NodeId, number>();
    for (let i = order.length - 1; i >= 0; i--) {
      const id = order[i];
      const kids = kidsOf(id);
      let stacked = 0;
      kids.forEach((kid, idx) => {
        stacked += gapBefore(kids, idx) + band.get(kid)!;
      });
      band.set(id, Math.max(rowHeight(byId.get(id)!), stacked));
    }

    // Hand each child its slice of the parent's band, root first.
    const local = new Map<NodeId, XY>();
    const bandTop = new Map<NodeId, number>([[root, 0]]);
    let maxDepth = 0;
    for (const id of order) {
      const kids = kidsOf(id);
      const start = bandTop.get(id)!;
      const height = band.get(id)!;
      let y = start + height / 2;
      if (kids.length) {
        let stacked = 0;
        kids.forEach((kid, idx) => {
          stacked += gapBefore(kids, idx) + band.get(kid)!;
        });
        let cursor = start + (height - stacked) / 2;
        kids.forEach((kid, idx) => {
          cursor += gapBefore(kids, idx);
          bandTop.set(kid, cursor);
          cursor += band.get(kid)!;
        });
        const first = kids[0];
        const last = kids[kids.length - 1];
        const middle =
          (bandTop.get(first)! + band.get(first)! / 2 + bandTop.get(last)! + band.get(last)! / 2) / 2;
        const half = rowHeight(byId.get(id)!) / 2;
        y = Math.min(Math.max(middle, start + half), start + height - half);
      }
      maxDepth = Math.max(maxDepth, depth.get(id)!);
      local.set(id, { x: depth.get(id)! * levelSep, y: Math.round(y) });
    }
    return { root, local, width: maxDepth * levelSep, height: band.get(root)! };
  };

  const drop = (block: Block, x: number, y: number) => {
    for (const [id, p] of block.local) positions.set(id, { x: x + p.x, y: y + p.y });
  };

  let top = 0;
  let looseCols = MAX_LOOSE_COLS;
  const trees = roots.map((root) => placeBlock(root, (id) => children.get(id)!));
  const stackedHeight = trees.reduce((sum, tree) => sum + tree.height + COMPONENT_GAP, 0);

  if (stackedHeight <= PACK_MIN_HEIGHT) {
    // Small map: whole trees, one under the other.
    for (const tree of trees) {
      drop(tree, 0, top);
      top += tree.height + COMPONENT_GAP;
    }
  } else {
    // Large map: one tall strip would be unusable. Cut the trees at their
    // overlay links, so every cabled island (typically a site) is a block of
    // its own, and flow the blocks into columns, in name order.
    const overlayKids = new Set(viaOverlay);
    const cabled = new Map<NodeId, NodeId[]>();
    for (const [id, kids] of children) {
      cabled.set(id, overlayKids.size ? kids.filter((kid) => !overlayKids.has(kid)) : kids);
    }
    const blockName = (root: NodeId) => {
      const node = byId.get(root)!;
      return node.meraki?.site_name || node.group_name || node.label;
    };
    const blocks = [...roots, ...viaOverlay]
      .map((root) => placeBlock(root, (id) => cabled.get(id)!))
      .sort(
        (a, b) =>
          blockName(a.root).localeCompare(blockName(b.root), undefined, { numeric: true, sensitivity: 'base' }) ||
          String(a.root).localeCompare(String(b.root)),
      );

    let area = 0;
    let tallest = 0;
    for (const block of blocks) {
      area += (block.width + levelSep) * (block.height + PACK_GAP_Y);
      tallest = Math.max(tallest, block.height);
    }
    const columnHeight = Math.max(tallest, Math.sqrt(area / PACK_ASPECT));

    let x = 0;
    let y = 0;
    let columnWidth = 0;
    let bottom = 0;
    for (const block of blocks) {
      if (y > 0 && y + block.height > columnHeight) {
        x += columnWidth + levelSep;
        y = 0;
        columnWidth = 0;
      }
      drop(block, x, y);
      columnWidth = Math.max(columnWidth, block.width);
      y += block.height + PACK_GAP_Y;
      bottom = Math.max(bottom, y);
    }
    top = bottom - PACK_GAP_Y + COMPONENT_GAP;
    looseCols = Math.max(MAX_LOOSE_COLS, Math.floor((x + columnWidth) / levelSep) + 1);
  }

  // Devices with no links at all: a compact grid under the trees.
  if (loose.length) {
    loose.sort((a, b) => group.get(a.id)!.localeCompare(group.get(b.id)!) || compareLabels(a, b));
    const cols = Math.max(1, Math.min(looseCols, Math.ceil(Math.sqrt(loose.length))));
    loose.forEach((n, idx) => {
      positions.set(n.id, {
        x: (idx % cols) * levelSep,
        y: Math.round(top + DEVICE_ROW_H / 2 + Math.floor(idx / cols) * DEVICE_ROW_H),
      });
    });
  }

  return positions;
}

/**
 * Groups whose frame (the bounding box of their members, padded) would also
 * enclose a node of another group - e.g. a hub site whose appliance sits in
 * the middle of its spokes. Their frame is not drawn.
 */
export function crowdedGroups(
  placed: { group: string; x: number; y: number }[],
  padX: number,
  padY: number,
): Set<string> {
  const boxes = new Map<string, { x0: number; y0: number; x1: number; y1: number }>();
  for (const p of placed) {
    if (!p.group) continue;
    const box = boxes.get(p.group);
    if (!box) {
      boxes.set(p.group, { x0: p.x, y0: p.y, x1: p.x, y1: p.y });
    } else {
      box.x0 = Math.min(box.x0, p.x);
      box.y0 = Math.min(box.y0, p.y);
      box.x1 = Math.max(box.x1, p.x);
      box.y1 = Math.max(box.y1, p.y);
    }
  }
  const crowded = new Set<string>();
  for (const [key, box] of boxes) {
    const x0 = box.x0 - padX;
    const x1 = box.x1 + padX;
    const y0 = box.y0 - padY;
    const y1 = box.y1 + padY;
    for (const p of placed) {
      if (p.group !== key && p.x >= x0 && p.x <= x1 && p.y >= y0 && p.y <= y1) {
        crowded.add(key);
        break;
      }
    }
  }
  return crowded;
}
