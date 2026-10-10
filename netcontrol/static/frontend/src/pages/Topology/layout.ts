import type { TopologyEdge, TopologyNode } from '@/api/topology';

import { nodeProvider, PROVIDER_ORDER } from './helpers';

// Tidy top-down tree layout: the default arrangement of the map.
//
// The map is split by source first - the inventory, then each integration
// (Meraki, Cato, Cisco FMC, Palo Alto Panorama, Appgate SDP, AWS, Azure, GCP) - and each source is drawn as a
// region of its own, side by side, so no source's devices end up
// scattered among another's. Links between sources are still drawn; they
// just do not shape the layout.
//
// Within a source every connected part of the network becomes a tree that
// grows down from its most central gateway. Each node owns a horizontal span
// exactly as wide as its subtree, so no two nodes (or their labels) can
// overlap, and the result is deterministic - the same data always opens the
// same way. Many devices of one site hanging off a node with nothing below
// them (access points, remote users) wrap into a grid instead of one endless
// row. A device with no links at all (dormant, offline, a sensor nothing
// reports a neighbour for) is drawn with its site: in a grid under the site's
// gateway, after its other devices. Only devices whose whole site has no
// links (or that belong to no site) are left for a grid under the trees.
//
// A node's children sit in a row under it, in site name order. A row too wide
// for the room it is given (hundreds of sites hanging off a VPN hub) wraps
// onto the next, so the hub stays on top of one compact block. A source's
// trees are flowed into rows the same way.
//
// The sites hanging off a node (a VPN hub's spokes, a VPC's peers, the Cato
// backbone's PoPs) are linked to it by a comb instead of a fan of curves:
// down from the node to a bar above their row and straight down into each.
// When they wrap onto several rows a trunk down the left of the block
// carries the bar to each lower row. Drawn as curves, the links to the far
// sites would cross the sites between, and those to a lower row would run
// through the boxes of the row above.

type NodeId = number | string;

export interface XY {
  x: number;
  y: number;
}

/** Labels longer than this are shortened on the map (the tooltip keeps the full name). */
export const TIDY_LABEL_MAX = 44;

const LABEL_CHAR_PX = 6.6;
// Width a node takes in its row: its label, padded.
const MIN_SLOT_W = 120;
const SLOT_PAD = 28;
// Vertical step from a node to its children.
const LEVEL_H = 170;
// A comb's bar runs this far above the top of the row of sites it serves:
// clear of their titles, and of the row above.
const BAR_ABOVE = 70;
// Room at the left of a node's rows for the comb's trunk, when its sites
// wrap onto more than one row.
const TRUNK_W = 50;
// A comb's drop into a site with WAN uplinks drawn above it comes down this
// far beside the uplinks and turns in, instead of running through them.
const HEAD_SIDE = 70;
// WAN uplinks are drawn in a row this far above their appliance.
const HEAD_H = 110;
const GROUP_GAP = 56;
// This many leaves of one site under one node wrap into a grid.
const GRID_MIN = 8;
const GRID_ROW_H = 100;
const USER_ROW_H = 76;
// Width : height a grid of leaves aims for.
const GRID_ASPECT = 3;
const LOOSE_ROW_H = 100;
const MAX_LOOSE_COLS = 8;
// A row of children is never wrapped narrower than this.
const WRAP_MIN_W = 2400;
const PACK_GAP_X = 160;
const PACK_GAP_Y = 190;
// Width : height wrapped rows aim for.
const PACK_ASPECT = 1.7;
/**
 * Space between the outermost nodes of two sources side by side: room for
 * both their frames and the half of a long label that sticks out of each.
 */
export const SOURCE_GAP = 600;

// Logical adjacencies ride on top of the physical network; the tree follows
// cables first and only uses these to reach parts nothing else connects.
// A management link (an FMC and the FTD it manages, a Panorama and its
// firewalls) is one of them.
const OVERLAY_PROTOCOLS = new Set(['vpn', 'vpn-ipsec', 'ospf', 'bgp', 'management']);

const GATEWAY_TYPES = new Set(['fortinet', 'paloalto_panos', 'cisco_asa', 'cisco_ftd']);

export function tidyLabel(label: string): string {
  return label.length > TIDY_LABEL_MAX ? `${label.slice(0, TIDY_LABEL_MAX - 1)}…` : label;
}

/** Site (Meraki network) or inventory group a node is drawn with. */
export function layoutGroupKey(node: TopologyNode): string {
  if (node.meraki?.site_id) return `m:${node.meraki.org_ref}:${node.meraki.site_id}`;
  return node.group_name ? `g:${node.group_name}` : '';
}

/** The sources on a map in the order they are drawn: the inventory, then each integration. */
export function orderSources(sources: Iterable<string>): string[] {
  const found = new Set(sources);
  const known = ['', ...PROVIDER_ORDER].filter((s) => found.has(s));
  const others = [...found].filter((s) => s && !PROVIDER_ORDER.includes(s)).sort();
  return [...known, ...others];
}

// The node a Cato account's tunnels all lead to.
const CATO_BACKBONE = 'cato:cloud';

function isBackbone(node: TopologyNode): boolean {
  return node.meraki?.provider === 'cato' && node.meraki.node_id === CATO_BACKBONE;
}

// Lower ranks sit closer to the root: gateways, then switching, then the rest.
function tierRank(node: TopologyNode): number {
  const kind = node.meraki?.kind ?? '';
  const category = (node.device_category ?? '').toLowerCase();
  // A Cato account hangs off its backbone: the backbone, then the PoPs, then
  // the sites and users connected to them.
  if (node.meraki?.provider === 'cato' && kind === 'cloud') return isBackbone(node) ? -2 : -1;
  if (kind === 'wan' || kind === 'vpn_peer') return 5;
  if (kind === 'appliance' || kind === 'vpc' || category === 'firewall' || category === 'router') return 0;
  if (node.device_type && GATEWAY_TYPES.has(node.device_type)) return 0;
  if (kind === 'switch' || category === 'switch') return 1;
  if (kind === 'external' || (!node.in_inventory && node.source !== 'meraki')) return 4;
  if (kind === 'wireless' || category === 'wireless' || category === 'phone') return 3;
  return 2;
}

/** About how wide a node's label is drawn in the tidy layout. */
export function labelWidth(label: string): number {
  return Math.min(TIDY_LABEL_MAX, label.length) * LABEL_CHAR_PX;
}

function slotWidth(node: TopologyNode): number {
  return Math.max(MIN_SLOT_W, Math.round(labelWidth(node.label) + SLOT_PAD));
}

function compareLabels(a: TopologyNode, b: TopologyNode): number {
  return (
    a.label.localeCompare(b.label, undefined, { numeric: true, sensitivity: 'base' }) ||
    String(a.id).localeCompare(String(b.id))
  );
}

/** A link of a comb, from the node to one of the sites hanging off it. */
interface CombLink {
  from: NodeId;
  to: NodeId;
  points: XY[];
}

interface Block {
  root: NodeId;
  /** Positions relative to the block's top-left corner. */
  local: Map<NodeId, XY>;
  /** Its combs, in the same coordinates. */
  links: CombLink[];
  width: number;
  height: number;
}

/** Leaves of one site under one node, drawn as a grid. */
interface Grid {
  members: NodeId[];
  cols: number;
  cellW: number;
  rowH: number;
  width: number;
  height: number;
}

/** What a node's rows of children are made of: child subtrees and grids. */
interface Unit {
  group: string;
  node?: NodeId;
  grid?: Grid;
}

/** One row of a node's children; `top` is its offset below the node. */
interface Row {
  units: Unit[];
  width: number;
  top: number;
}

export interface TidyTree {
  positions: Map<NodeId, XY>;
  /**
   * Which piece of its site each node is drawn in. A site whose devices the
   * tree spreads over several places (a VPC peered with a hub, devices in two
   * networks not linked to each other) is one piece per place, each framed on
   * its own. Nodes
   * that belong to no site are left out.
   */
  pieces: Map<NodeId, string>;
  /**
   * The links drawn as a comb (from a node to the sites hanging off it), by
   * edge id: the polyline from the node down to the site. Every other link
   * is left to be drawn as a curve.
   */
  routes: Map<NodeId, XY[]>;
}

export function tidyTreeLayout(nodes: TopologyNode[], edges: TopologyEdge[]): Map<NodeId, XY> {
  return tidyTree(nodes, edges).positions;
}

/** The polyline without repeated points or points midway along a straight line. */
export function straighten(points: XY[]): XY[] {
  const out: XY[] = [];
  for (const p of points) {
    const last = out[out.length - 1];
    if (last && last.x === p.x && last.y === p.y) continue;
    const before = out[out.length - 2];
    if (before && ((before.x === last.x && last.x === p.x) || (before.y === last.y && last.y === p.y))) out.pop();
    out.push(p);
  }
  return out;
}

/** A site's frame as drawn, and the name written above it. */
export interface TitledBox {
  x0: number;
  y0: number;
  x1: number;
  y1: number;
  name: string;
}

/**
 * The title to write above each frame: its name, shortened with an ellipsis
 * where it would run into the next frame to its right (a site of one node
 * with a long name is a narrow box under a wide title). `font` is the
 * title's size, `inset` how far into the frame it starts. About 0.6 em a
 * character, as everywhere titles are measured.
 */
export function fitTitles(boxes: TitledBox[], font: number, inset: number): string[] {
  const band = font + 4;
  const charW = font * 0.6;
  return boxes.map((box) => {
    let limit = Infinity;
    for (const other of boxes) {
      if (other.x0 > box.x0 && other.y0 - band < box.y0 && other.y1 > box.y0 - band) limit = Math.min(limit, other.x0);
    }
    const start = box.x0 + inset;
    if (start + box.name.length * charW <= limit) return box.name;
    const fits = Math.max(8, Math.floor((limit - start - 8) / charW));
    return fits >= box.name.length ? box.name : `${box.name.slice(0, fits - 1)}…`;
  });
}

export function tidyTree(nodes: TopologyNode[], edges: TopologyEdge[]): TidyTree {
  const positions = new Map<NodeId, XY>();
  const pieces = new Map<NodeId, string>();
  const routes = new Map<NodeId, XY[]>();
  if (!nodes.length) return { positions, pieces, routes };

  const group = new Map<NodeId, string>();
  const source = new Map<NodeId, string>();
  const bySource = new Map<string, TopologyNode[]>();
  for (const n of nodes) {
    group.set(n.id, layoutGroupKey(n));
    const key = nodeProvider(n);
    source.set(n.id, key);
    const members = bySource.get(key);
    if (members) members.push(n);
    else bySource.set(key, [n]);
  }

  // Pieces of a site: members joined by a link of the tree, or placed side
  // by side as siblings or in a grid.
  const leader = new Map<NodeId, NodeId>();
  const find = (id: NodeId): NodeId => {
    let at = id;
    while (leader.get(at) !== undefined && leader.get(at) !== at) at = leader.get(at)!;
    leader.set(id, at);
    return at;
  };
  const join = (a: NodeId, b: NodeId) => {
    if (group.get(a) !== group.get(b) || !group.get(a)) return;
    leader.set(find(a), find(b));
  };

  // The sources side by side, their tops level.
  let left = 0;
  for (const key of orderSources(bySource.keys())) {
    const inside = edges.filter((e) => source.get(e.from) === key && source.get(e.to) === key);
    const region = placeSource(bySource.get(key)!, inside, group, join);
    let x0 = Infinity;
    let x1 = -Infinity;
    for (const p of region.local.values()) {
      x0 = Math.min(x0, p.x);
      x1 = Math.max(x1, p.x);
    }
    for (const [id, p] of region.local) positions.set(id, { x: p.x - x0 + left, y: p.y });
    for (const [id, points] of region.routes) routes.set(id, points.map((p) => ({ x: p.x - x0 + left, y: p.y })));
    left += x1 - x0 + SOURCE_GAP;
  }

  for (const n of nodes) {
    const site = group.get(n.id)!;
    if (site) pieces.set(n.id, `${site}#${String(find(n.id))}`);
  }
  return { positions, pieces, routes };
}

// One key for both directions of a link between two nodes. The type is kept
// so a node 7 and a node "7" stay apart.
function pairKey(a: NodeId, b: NodeId): string {
  return JSON.stringify([`${typeof a}:${a}`, `${typeof b}:${b}`].sort());
}

/** Lay one source's nodes out as trees, with its top-left corner at 0,0. */
function placeSource(
  nodes: TopologyNode[],
  edges: TopologyEdge[],
  group: Map<NodeId, string>,
  join: (a: NodeId, b: NodeId) => void,
): { local: Map<NodeId, XY>; routes: Map<NodeId, XY[]> } {
  const local = new Map<NodeId, XY>();
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

  const rank = new Map<NodeId, number>();
  const slot = new Map<NodeId, number>();
  const siteName = new Map<string, string>();
  for (const n of nodes) {
    rank.set(n.id, tierRank(n));
    slot.set(n.id, slotWidth(n));
    siteName.set(group.get(n.id)!, n.meraki?.site_name || n.group_name || '');
  }
  // Sites in name order.
  const compareSites = (a: string, b: string) =>
    siteName.get(a)!.localeCompare(siteName.get(b)!, undefined, { numeric: true, sensitivity: 'base' }) ||
    a.localeCompare(b);

  const rootOrder = [...nodes].sort(
    (a, b) =>
      rank.get(a.id)! - rank.get(b.id)! ||
      adjacency.get(b.id)!.size - adjacency.get(a.id)!.size ||
      compareLabels(a, b),
  );

  const visited = new Set<NodeId>();
  const children = new Map<NodeId, NodeId[]>();
  // Nodes whose only way into the tree was an overlay link (a VPN tunnel).
  const viaOverlay: NodeId[] = [];
  const roots: NodeId[] = [];
  const loose: TopologyNode[] = [];
  // How close to its root each tree node is: its place in the breadth-first walk.
  const bfsIndex = new Map<NodeId, number>();

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
        bfsIndex.set(id, order.length);
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
          return compareSites(ga, gb);
        }
        return rank.get(a)! - rank.get(b)! || compareLabels(byId.get(a)!, byId.get(b)!);
      });
    }
  }

  // A WAN uplink is drawn in a row just above its appliance, as in a site
  // box. As one of its children it would be placed among everything else the
  // appliance has - beside a switch with a hundred access points, a screen
  // away from it.
  const overlayAdopted = new Set(viaOverlay);
  const heads = new Map<NodeId, NodeId[]>();
  for (const [id, kids] of children) {
    const up = kids.filter(
      (kid) =>
        byId.get(kid)!.meraki?.kind === 'wan' &&
        !children.get(kid)!.length &&
        !overlayAdopted.has(kid) &&
        group.get(kid) === group.get(id),
    );
    if (!up.length) continue;
    heads.set(id, up);
    children.set(id, kids.filter((kid) => !up.includes(kid)));
  }
  const headRoom = (id: NodeId) => (heads.has(id) ? HEAD_H : 0);
  const headsWidth = (id: NodeId) => (heads.get(id) ?? []).reduce<number>((sum, wan) => sum + slot.get(wan)!, 0);

  // Many leaves of one site under one node (access points on a switch,
  // hundreds of remote users on a PoP) would be one endless row: they wrap
  // into a grid under it, and stay with it on a large map instead of each
  // being a block of its own.
  const grids = new Map<NodeId, Grid[]>();
  const gridded = new Set<NodeId>();
  const gridOf = (members: NodeId[], rowH: number): Grid => {
    const cellW = Math.max(...members.map((m) => slot.get(m)!));
    const cols = Math.max(
      1,
      Math.min(members.length, Math.round(Math.sqrt((members.length * rowH * GRID_ASPECT) / cellW))),
    );
    return { members, cols, cellW, rowH, width: cols * cellW, height: Math.ceil(members.length / cols) * rowH };
  };
  for (const [id, kids] of children) {
    const leaves = new Map<string, NodeId[]>();
    for (const kid of kids) {
      if (children.get(kid)!.length || heads.has(kid)) continue;
      const site = group.get(kid)!;
      const members = leaves.get(site);
      if (members) members.push(kid);
      else leaves.set(site, [kid]);
    }
    const own: Grid[] = [];
    for (const members of leaves.values()) {
      if (members.length < GRID_MIN) continue;
      const rowH = members.every((m) => byId.get(m)!.meraki?.kind === 'user') ? USER_ROW_H : GRID_ROW_H;
      own.push(gridOf(members, rowH));
    }
    if (!own.length) continue;
    grids.set(id, own);
    for (const grid of own) for (const member of grid.members) gridded.add(member);
    children.set(id, kids.filter((kid) => !gridded.has(kid)));
  }

  // A device with no links at all (dormant, offline, a sensor the API reports
  // no neighbour for) whose site is in a tree is drawn with it: a grid under
  // the site's gateway - its member closest to the top of the tree - after
  // the gateway's other devices. Under the trees it would split the site in
  // two, each part in a box of its own.
  const headed = new Set<NodeId>();
  for (const up of heads.values()) for (const wan of up) headed.add(wan);
  const closer = (a: NodeId, b: NodeId) =>
    rank.get(a)! - rank.get(b)! || bfsIndex.get(a)! - bfsIndex.get(b)! || compareLabels(byId.get(a)!, byId.get(b)!);
  const anchors = new Map<string, NodeId>();
  for (const id of children.keys()) {
    const site = group.get(id)!;
    if (!site || headed.has(id) || gridded.has(id)) continue;
    const best = anchors.get(site);
    if (best === undefined || closer(id, best) < 0) anchors.set(site, id);
  }
  const strays = new Map<NodeId, NodeId[]>();
  const pile: TopologyNode[] = [];
  for (const n of loose) {
    const anchor = anchors.get(group.get(n.id)!);
    if (anchor === undefined) {
      pile.push(n);
      continue;
    }
    const members = strays.get(anchor);
    if (members) members.push(n.id);
    else strays.set(anchor, [n.id]);
  }
  const strayGrids = new Set<Grid>();
  for (const [anchor, members] of strays) {
    members.sort((a, b) => compareLabels(byId.get(a)!, byId.get(b)!));
    const grid = gridOf(members, GRID_ROW_H);
    strayGrids.add(grid);
    const own = grids.get(anchor);
    if (own) own.push(grid);
    else grids.set(anchor, [grid]);
  }

  // A node's row of children: its own site first, then site by site, each
  // site's grid after its other devices, and the devices with no links last.
  const unitsOf = (id: NodeId, kids: NodeId[]): Unit[] => {
    const own = group.get(id)!;
    const units: (Unit & { order: number })[] = kids.map((kid, idx) => ({ group: group.get(kid)!, node: kid, order: idx }));
    for (const grid of grids.get(id) ?? []) {
      units.push({ group: group.get(grid.members[0])!, grid, order: kids.length + (strayGrids.has(grid) ? 1 : 0) });
    }
    return units.sort((a, b) => {
      if (a.group !== b.group) {
        if (a.group === own) return -1;
        if (b.group === own) return 1;
        return compareSites(a.group, b.group);
      }
      return a.order - b.order;
    });
  };
  const gapBefore = (units: Unit[], idx: number) => (idx > 0 && units[idx].group !== units[idx - 1].group ? GROUP_GAP : 0);

  // Lay one tree out on its own, growing down from `root`. A node's children
  // sit in a row under it; a row wider than the room it is given wraps onto
  // the next, so a hub with hundreds of sites stays a compact block with the
  // hub on top instead of becoming one endless strip.
  const placeBlock = (root: NodeId): Block => {
    const order: NodeId[] = [root];
    const units = new Map<NodeId, Unit[]>();
    for (let i = 0; i < order.length; i++) {
      const list = unitsOf(order[i], children.get(order[i])!);
      units.set(order[i], list);
      for (const unit of list) if (unit.node !== undefined) order.push(unit.node);
    }

    // Size of every subtree, leaves first: its width, and how far it reaches
    // below the top of the row it sits in.
    const span = new Map<NodeId, number>();
    const depth = new Map<NodeId, number>();
    const rows = new Map<NodeId, Row[]>();
    // Nodes linked to the sites hanging off them by a comb, and those of
    // them whose sites wrap onto more than one row (they keep room for the
    // comb's trunk at their left).
    const combed = new Set<NodeId>();
    const trunked = new Set<NodeId>();
    const unitWidth = (unit: Unit) => (unit.grid ? unit.grid.width : span.get(unit.node!)!);
    const unitDepth = (unit: Unit) => (unit.grid ? unit.grid.height - unit.grid.rowH : depth.get(unit.node!)!);
    const rowWidth = (list: Unit[]) => list.reduce((sum, unit, idx) => sum + gapBefore(list, idx) + unitWidth(unit), 0);
    for (let i = order.length - 1; i >= 0; i--) {
      const id = order[i];
      const site = group.get(id)!;
      const list = units.get(id)!;
      let area = 0;
      let widest = 0;
      for (const unit of list) {
        area += (unitWidth(unit) + GROUP_GAP) * (unitDepth(unit) + LEVEL_H);
        widest = Math.max(widest, unitWidth(unit));
      }
      // Wrapping is for many children; one wide subtree (a PoP with hundreds
      // of users) does not push its few siblings onto rows of their own. The
      // Cato backbone's PoPs stay in one row: its links to them are always
      // drawn, and read best as one comb along the top of the account.
      const limit = isBackbone(byId.get(id)!)
        ? Infinity
        : Math.max(WRAP_MIN_W, widest * 2, Math.sqrt(area * PACK_ASPECT));
      const own: Row[] = [];
      let row: Unit[] = [];
      let width = 0;
      for (const unit of list) {
        let gap = row.length && row[row.length - 1].group !== unit.group ? GROUP_GAP : 0;
        if (row.length && width + gap + unitWidth(unit) > limit) {
          own.push({ units: row, width, top: 0 });
          row = [];
          width = 0;
          gap = 0;
        }
        row.push(unit);
        width += gap + unitWidth(unit);
      }
      if (row.length) own.push({ units: row, width, top: 0 });
      // A gateway sits over its own devices. At the front of its row they
      // would put it at the far left of the other sites hanging off it, its
      // links to them all fanning out one way, over each other. Its own
      // devices go in the middle of the first row instead, the other sites
      // split about evenly to either side, in their order.
      const first = own[0]?.units ?? [];
      const mine = first.filter((unit) => unit.group === site);
      const others = first.filter((unit) => unit.group !== site);
      if (mine.length && others.length) {
        const total = others.reduce((sum, unit) => sum + unitWidth(unit), 0);
        let split = 0;
        let leftWidth = 0;
        while (split < others.length && leftWidth < total / 2) leftWidth += unitWidth(others[split++]);
        own[0].units = [...others.slice(0, split), ...mine, ...others.slice(split)];
        own[0].width = rowWidth(own[0].units);
      }
      // Two or more sites hanging off the node are linked to it by a comb;
      // when some are on a lower row, its trunk needs room at the left.
      const spokes = own.reduce((sum, r) => sum + r.units.filter((unit) => unit.group !== site).length, 0);
      if (spokes >= 2) {
        combed.add(id);
        if (own.slice(1).some((r) => r.units.some((unit) => unit.group !== site))) trunked.add(id);
      }
      // Each row a level below the deepest subtree of the one above it.
      let top = LEVEL_H;
      let reach = 0;
      for (const r of own) {
        r.top = top;
        reach = top + Math.max(...r.units.map(unitDepth));
        top = reach + LEVEL_H;
      }
      rows.set(id, own);
      const rowsWidth = Math.max(0, ...own.map((r) => r.width));
      span.set(id, Math.max(slot.get(id)!, headsWidth(id), (trunked.has(id) ? TRUNK_W : 0) + rowsWidth));
      depth.set(id, headRoom(id) + reach);
    }

    // Hand each child its slice of the parent's span, root first.
    const local = new Map<NodeId, XY>();
    const left = new Map<NodeId, number>([[root, 0]]);
    const level = new Map<NodeId, number>([[root, headRoom(root)]]);
    for (const id of order) {
      const start = left.get(id)!;
      const width = span.get(id)!;
      const y = level.get(id)!;
      const site = group.get(id)!;
      const centers: number[] = [];
      const ownCenters: number[] = [];
      // The rows keep clear of the comb's trunk, at the left of the span.
      const inset = trunked.has(id) ? TRUNK_W : 0;
      for (const row of rows.get(id)!) {
        let cursor = start + inset + (width - inset - row.width) / 2;
        row.units.forEach((unit, idx) => {
          cursor += gapBefore(row.units, idx);
          const center = cursor + unitWidth(unit) / 2;
          centers.push(center);
          if (unit.group === site) ownCenters.push(center);
          if (unit.node !== undefined) {
            left.set(unit.node, cursor);
            level.set(unit.node, y + row.top + headRoom(unit.node));
          } else {
            const grid = unit.grid!;
            const gridLeft = cursor;
            grid.members.forEach((member, i) => {
              local.set(member, {
                x: Math.round(gridLeft + (i % grid.cols) * grid.cellW + grid.cellW / 2),
                y: y + row.top + Math.floor(i / grid.cols) * grid.rowH,
              });
            });
          }
          cursor += unitWidth(unit);
        });
      }
      // A site's gateway sits over its own devices, not in the middle of the
      // other sites hanging off it, so its frame stays clear of them.
      const over = site.startsWith('m:') && ownCenters.length ? ownCenters : centers;
      let x = over.length ? (Math.min(...over) + Math.max(...over)) / 2 : start + width / 2;
      const half = Math.max(slot.get(id)!, headsWidth(id)) / 2;
      x = Math.round(Math.min(Math.max(x, start + inset + half), start + width - half));
      local.set(id, { x, y });
      // The WAN uplinks: a row above the appliance, centered on it.
      let wanLeft = x - headsWidth(id) / 2;
      for (const wan of heads.get(id) ?? []) {
        local.set(wan, { x: Math.round(wanLeft + slot.get(wan)! / 2), y: y - HEAD_H });
        wanLeft += slot.get(wan)!;
      }
    }

    // The combs, now every node has its place. Each link runs down from the
    // node to the bar above the first row, along the trunk (for a lower
    // row) to that row's bar, along it, and straight down into its site. The
    // links share their stretches, so together they draw as one comb.
    const links: CombLink[] = [];
    for (const id of order) {
      if (!combed.has(id)) continue;
      const site = group.get(id)!;
      const at = local.get(id)!;
      const own = rows.get(id)!;
      const barY = (row: Row) => at.y + row.top - BAR_ABOVE;
      const trunkX = left.get(id)! + TRUNK_W / 2;
      const stem = [at, { x: at.x, y: barY(own[0]) }];
      own.forEach((row, idx) => {
        const lead = idx ? [...stem, { x: trunkX, y: barY(own[0]) }, { x: trunkX, y: barY(row) }] : stem;
        for (const unit of row.units) {
          if (unit.group === site) continue;
          for (const end of unit.node !== undefined ? [unit.node] : unit.grid!.members) {
            const to = local.get(end)!;
            // A site with WAN uplinks over its gateway is entered from the
            // side, beside the uplinks (and their labels), not through them.
            const up = heads.get(end);
            const dropX = up
              ? local.get(up[0])!.x - Math.max(HEAD_SIDE, slot.get(up[0])! / 2)
              : to.x;
            const points = [...lead, { x: dropX, y: barY(row) }, { x: dropX, y: to.y }, to];
            links.push({ from: id, to: end, points: straighten(points) });
          }
        }
      });
    }
    return { root, local, links, width: span.get(root)!, height: depth.get(root)! };
  };

  // The trees side by side, flowed into rows of about the same width.
  const blocks = roots.map(placeBlock);
  let area = 0;
  let widest = 0;
  for (const block of blocks) {
    area += (block.width + PACK_GAP_X) * (block.height + PACK_GAP_Y);
    widest = Math.max(widest, block.width);
  }
  const rowLimit = Math.max(widest, Math.sqrt(area * PACK_ASPECT));
  let x = 0;
  let y = 0;
  let rowHeight = 0;
  let right = 0;
  const links: CombLink[] = [];
  for (const block of blocks) {
    if (x > 0 && x + block.width > rowLimit) {
      x = 0;
      y += rowHeight + PACK_GAP_Y;
      rowHeight = 0;
    }
    for (const [id, p] of block.local) local.set(id, { x: x + p.x, y: y + p.y });
    for (const link of block.links) {
      links.push({ ...link, points: link.points.map((p) => ({ x: x + p.x, y: y + p.y })) });
    }
    rowHeight = Math.max(rowHeight, block.height);
    right = Math.max(right, x + block.width);
    x += block.width + PACK_GAP_X;
  }
  const bottom = blocks.length ? y + rowHeight : 0;

  for (const [id, up] of heads) {
    for (const wan of up) join(id, wan);
  }
  for (const [id, own] of grids) {
    for (const { members } of own) {
      for (const member of members) {
        join(member, members[0]);
        join(member, id);
      }
    }
  }
  for (const [id, kids] of children) {
    kids.forEach((kid, idx) => {
      join(id, kid);
      if (idx) join(kids[idx - 1], kid);
    });
  }

  // Devices with no links at all whose site has none either (or that belong
  // to no site): a compact grid under the trees.
  if (pile.length) {
    pile.sort((a, b) => compareSites(group.get(a.id)!, group.get(b.id)!) || compareLabels(a, b));
    pile.forEach((n, idx) => {
      if (idx) join(pile[idx - 1].id, n.id);
    });
    const cellW = Math.max(...pile.map((n) => slot.get(n.id)!));
    const cols = Math.max(1, Math.min(pile.length, Math.max(MAX_LOOSE_COLS, Math.floor(right / cellW))));
    const looseTop = blocks.length ? bottom + PACK_GAP_Y : 0;
    pile.forEach((n, idx) => {
      local.set(n.id, {
        x: Math.round((idx % cols) * cellW + cellW / 2),
        y: looseTop + Math.floor(idx / cols) * LOOSE_ROW_H,
      });
    });
  }

  // Every link between a node and a site on its comb follows the comb; two
  // links between the same pair (a cable and a tunnel) are drawn over each other.
  const edgeIds = new Map<string, NodeId[]>();
  for (const e of edges) {
    if (e.from === e.to) continue;
    const key = pairKey(e.from, e.to);
    const ids = edgeIds.get(key);
    if (ids) ids.push(e.id);
    else edgeIds.set(key, [e.id]);
  }
  const routes = new Map<NodeId, XY[]>();
  for (const link of links) {
    for (const id of edgeIds.get(pairKey(link.from, link.to)) ?? []) routes.set(id, link.points);
  }

  return { local, routes };
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
