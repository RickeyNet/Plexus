/**
 * Routes for the links between two sources of the tidy layout (a Cato
 * vSocket and its AWS VPC, a vMX and its VPC...).
 *
 * Drawn as vis draws every other link, such a link would run straight
 * across the sites of its own source and of every source between the two.
 * Instead it goes up from each end, around the other sites' boxes and
 * nodes, to a lane above the top of every source, and across: up, out of
 * the source's frame, over and down. Links whose stretches of lane overlap
 * get lanes of their own, the shortest lowest, so they nest instead of
 * crossing.
 *
 * The way up from each end is the cheapest path on a grid made of the
 * edges of what is in the way (orthogonal routing over the "Hanan grid"):
 * every turn costs something, running through a box or past a node costs
 * a lot, and running along a route already placed a little.
 */

import { straighten, type XY } from './layout';

// Shared with the tidy layout, which draws its combs with the same polylines.
export { straighten };

type NodeId = number | string;

export interface SourceLink {
  id: NodeId;
  from: NodeId;
  to: NodeId;
}

/** A site's box as drawn (title included) and the nodes in it. */
export interface RouteBox {
  x0: number;
  y0: number;
  x1: number;
  y1: number;
  ids: NodeId[];
  /** Where its title is written: a route leaving the box keeps off it too. */
  title?: { x0: number; y0: number; x1: number; y1: number };
}

// The lowest lane, above the top of the sources (and their titles).
const LANE_ABOVE = 70;
const LANE_STEP = 18;
// Stretches of lane closer than this share no lane.
const LANE_MARGIN = 24;
// A route keeps this far from the centre of any node not in a box...
const NODE_CLEAR = 44;
// ...and this far from the edge of a box.
const BOX_CLEAR = 14;
// Two routes closer than this would draw as one line.
const ROUTE_CLEAR = 10;
// Costs, per pixel of route, beside its length.
const BLOCKED_COST = 40;
const ALONGSIDE_COST = 2;
const BEND_COST = 150;
// How far beside its node a route looks for a way up, widened in turn
// while every way up runs through something.
const REACHES = [800, 2400, 8000];

interface Rect {
  x0: number;
  y0: number;
  x1: number;
  y1: number;
}

interface Way {
  points: XY[];
  cost: number;
  blocked: number;
}

/**
 * The polyline of each link, from its `from` node to its `to` node.
 * `top` is the top of the highest source frame; `boxes` are the site boxes
 * a route keeps out of (but for the boxes of its own ends);
 * `labelWidths` the width of the label under each node, which it keeps off
 * as well.
 */
export function routeSourceLinks(
  links: SourceLink[],
  positions: Map<NodeId, XY>,
  top: number,
  boxes: RouteBox[] = [],
  labelWidths: Map<NodeId, number> = new Map(),
): Map<NodeId, XY[]> {
  const routes = new Map<NodeId, XY[]>();
  const placed = links.filter((l) => positions.has(l.from) && positions.has(l.to) && l.from !== l.to);
  if (!placed.length) return routes;
  const base = top - LANE_ABOVE;
  const boxOf = new Map<NodeId, RouteBox>();
  for (const box of boxes) for (const id of box.ids) boxOf.set(id, box);
  const loose = [...positions].filter(([id]) => !boxOf.has(id));
  // The stretches of the routes placed so far.
  const taken: Rect[] = [];

  function wayUp(id: NodeId): XY[] {
    let best: Way | null = null;
    for (const reach of REACHES) {
      const way = searchUp(id, reach);
      if (!best || way.cost < best.cost) best = way;
      if (!way.blocked) break;
    }
    for (let i = 1; i < best!.points.length; i++) {
      const [a, b] = [best!.points[i - 1], best!.points[i]];
      taken.push({
        x0: Math.min(a.x, b.x) - ROUTE_CLEAR,
        x1: Math.max(a.x, b.x) + ROUTE_CLEAR,
        y0: Math.min(a.y, b.y) - ROUTE_CLEAR,
        y1: Math.max(a.y, b.y) + ROUTE_CLEAR,
      });
    }
    return best!.points;
  }

  // The cheapest way from node `id` up to the row `base`, looking no
  // further than `reach` to either side.
  function searchUp(id: NodeId, reach: number): Way {
    const at = positions.get(id)!;
    if (at.y <= base) return { points: [at], cost: 0, blocked: 0 };
    const own = boxOf.get(id);
    const bounds = { x0: at.x - reach, x1: at.x + reach, y0: base, y1: at.y + NODE_CLEAR + BOX_CLEAR };
    const within = (r: Rect) => r.x1 > bounds.x0 && r.x0 < bounds.x1 && r.y1 > bounds.y0 && r.y0 < bounds.y1;
    const blocks: Rect[] = [];
    for (const box of boxes) {
      const r = { x0: box.x0 - BOX_CLEAR, x1: box.x1 + BOX_CLEAR, y0: box.y0 - BOX_CLEAR, y1: box.y1 + BOX_CLEAR };
      if (box !== own && within(r)) blocks.push(r);
    }
    if (own?.title) {
      const t = own.title;
      blocks.push({ x0: t.x0 - ROUTE_CLEAR, x1: t.x1 + ROUTE_CLEAR, y0: t.y0 - ROUTE_CLEAR, y1: t.y1 + ROUTE_CLEAR });
    }
    const nodes = own ? [...loose, ...own.ids.map((n) => [n, positions.get(n)] as const)] : loose;
    for (const [other, p] of nodes) {
      if (other === id || !p) continue;
      // The node, and the label written under it.
      const half = Math.max(NODE_CLEAR, (labelWidths.get(other) ?? 0) / 2 + ROUTE_CLEAR);
      const r = { x0: p.x - half, x1: p.x + half, y0: p.y - NODE_CLEAR, y1: p.y + NODE_CLEAR };
      if (within(r)) blocks.push(r);
    }
    const alongside = taken.filter(within);

    const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));
    const xs = unique([at.x, bounds.x0, bounds.x1, ...[...blocks, ...alongside].flatMap((r) => [r.x0, r.x1])].map((x) => clamp(x, bounds.x0, bounds.x1)));
    const ys = unique([at.y, bounds.y0, bounds.y1, ...[...blocks, ...alongside].flatMap((r) => [r.y0, r.y1])].map((y) => clamp(y, bounds.y0, bounds.y1)));
    const nx = xs.length;
    const ny = ys.length;
    // Per stretch of grid line: how many blocks, and earlier routes, it runs
    // through. Row stretches are [j * nx + i] (row j, from xs[i] to xs[i+1]),
    // column stretches [i * ny + j].
    const rowBlocked = new Uint16Array(nx * ny);
    const colBlocked = new Uint16Array(nx * ny);
    const rowAlong = new Uint16Array(nx * ny);
    const colAlong = new Uint16Array(nx * ny);
    const mark = (r: Rect, rows: Uint16Array, cols: Uint16Array) => {
      const [i0, i1] = [indexOf(xs, clamp(r.x0, bounds.x0, bounds.x1)), indexOf(xs, clamp(r.x1, bounds.x0, bounds.x1))];
      const [j0, j1] = [indexOf(ys, clamp(r.y0, bounds.y0, bounds.y1)), indexOf(ys, clamp(r.y1, bounds.y0, bounds.y1))];
      for (let j = j0 + 1; j < j1; j++) for (let i = i0; i < i1; i++) rows[j * nx + i]++;
      for (let i = i0 + 1; i < i1; i++) for (let j = j0; j < j1; j++) cols[i * ny + j]++;
    };
    for (const r of blocks) mark(r, rowBlocked, colBlocked);
    for (const r of alongside) mark(r, rowAlong, colAlong);

    // A* over (grid point, heading): 0 along a row, 1 along a column.
    const start = indexOf(xs, at.x) + indexOf(ys, at.y) * nx;
    const cost = new Float64Array(nx * ny * 2).fill(Infinity);
    const from = new Int32Array(nx * ny * 2).fill(-1);
    const heap = new Heap();
    for (const heading of [0, 1]) {
      cost[start * 2 + heading] = 0;
      heap.push(at.y - base, start * 2 + heading);
    }
    let goal = -1;
    while (heap.size) {
      const [f, state] = heap.pop();
      const point = state >> 1;
      const heading = state & 1;
      const i = point % nx;
      const j = (point - i) / nx;
      if (f - (ys[j] - base) > cost[state]) continue;
      if (j === 0) {
        goal = state;
        break;
      }
      const steps: [number, number, number, number, number][] = [];
      if (i > 0) steps.push([point - 1, 0, xs[i] - xs[i - 1], rowBlocked[j * nx + i - 1], rowAlong[j * nx + i - 1]]);
      if (i < nx - 1) steps.push([point + 1, 0, xs[i + 1] - xs[i], rowBlocked[j * nx + i], rowAlong[j * nx + i]]);
      if (j > 0) steps.push([point - nx, 1, ys[j] - ys[j - 1], colBlocked[i * ny + j - 1], colAlong[i * ny + j - 1]]);
      if (j < ny - 1) steps.push([point + nx, 1, ys[j + 1] - ys[j], colBlocked[i * ny + j], colAlong[i * ny + j]]);
      for (const [next, nextHeading, length, blocked, along] of steps) {
        const c =
          cost[state] +
          length * (1 + (blocked ? BLOCKED_COST : 0) + along * ALONGSIDE_COST) +
          (nextHeading !== heading && point !== start ? BEND_COST : 0);
        const to = next * 2 + nextHeading;
        if (c < cost[to]) {
          cost[to] = c;
          from[to] = state;
          heap.push(c + ys[Math.floor(next / nx)] - base, to);
        }
      }
    }

    const points: XY[] = [];
    let blocked = 0;
    for (let state = goal; state >= 0; state = from[state]) {
      const point = state >> 1;
      points.push({ x: xs[point % nx], y: ys[Math.floor(point / nx)] });
    }
    points.reverse();
    points[0] = at;
    for (let k = 1; k < points.length; k++) {
      const [a, b] = [points[k - 1], points[k]];
      for (const r of blocks) blocked += overlap(a, b, r);
    }
    return { points: straighten(points), cost: cost[goal], blocked };
  }

  // Lanes: each link spans the stretch between its ends' ways up; the
  // shortest go lowest.
  const spans = placed
    .map((l) => {
      const a = positions.get(l.from)!;
      const b = positions.get(l.to)!;
      return { link: l, length: Math.abs(a.x - b.x) };
    })
    .sort((p, q) => p.length - q.length)
    .map(({ link }) => {
      const up = wayUp(link.from);
      const down = wayUp(link.to);
      const [ax, bx] = [up[up.length - 1].x, down[down.length - 1].x];
      return { link, up, down, x0: Math.min(ax, bx), x1: Math.max(ax, bx) };
    })
    .sort((p, q) => p.x1 - p.x0 - (q.x1 - q.x0) || p.x0 - q.x0);
  const lanes: { x0: number; x1: number }[][] = [];
  for (const span of spans) {
    let lane = lanes.findIndex((taken) =>
      taken.every((t) => span.x1 + LANE_MARGIN < t.x0 || span.x0 - LANE_MARGIN > t.x1),
    );
    if (lane < 0) lane = lanes.push([]) - 1;
    lanes[lane].push(span);
    const laneY = base - lane * LANE_STEP;
    const { up, down } = span;
    // A way up ends on the row `base`, replaced by the lane; a node dragged
    // above the sources has no way up and joins the lane straight from itself.
    const toLane = (way: XY[]) => (way.length > 1 ? way.slice(0, -1) : way);
    const points = [
      ...toLane(up),
      { x: up[up.length - 1].x, y: laneY },
      { x: down[down.length - 1].x, y: laneY },
      ...toLane(down).reverse(),
    ];
    routes.set(span.link.id, straighten(points));
  }
  return routes;
}

function unique(values: number[]): number[] {
  return [...new Set(values)].sort((a, b) => a - b);
}

// The index of `value` in the sorted `values`, which holds it.
function indexOf(values: number[], value: number): number {
  let lo = 0;
  let hi = values.length - 1;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (values[mid] < value) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

// The length of the vertical or horizontal segment a-b inside `r`.
function overlap(a: XY, b: XY, r: Rect): number {
  if (a.y === b.y) {
    if (a.y <= r.y0 || a.y >= r.y1) return 0;
    return Math.max(0, Math.min(r.x1, Math.max(a.x, b.x)) - Math.max(r.x0, Math.min(a.x, b.x)));
  }
  if (a.x <= r.x0 || a.x >= r.x1) return 0;
  return Math.max(0, Math.min(r.y1, Math.max(a.y, b.y)) - Math.max(r.y0, Math.min(a.y, b.y)));
}

// A binary min-heap of (priority, value).
class Heap {
  private keys: number[] = [];
  private values: number[] = [];

  get size(): number {
    return this.keys.length;
  }

  push(key: number, value: number): void {
    const { keys, values } = this;
    let i = keys.length;
    keys.push(key);
    values.push(value);
    while (i > 0) {
      const parent = (i - 1) >> 1;
      if (keys[parent] <= key) break;
      keys[i] = keys[parent];
      values[i] = values[parent];
      i = parent;
    }
    keys[i] = key;
    values[i] = value;
  }

  pop(): [number, number] {
    const { keys, values } = this;
    const top: [number, number] = [keys[0], values[0]];
    const key = keys.pop()!;
    const value = values.pop()!;
    if (keys.length) {
      let i = 0;
      for (;;) {
        let child = 2 * i + 1;
        if (child >= keys.length) break;
        if (child + 1 < keys.length && keys[child + 1] < keys[child]) child++;
        if (keys[child] >= key) break;
        keys[i] = keys[child];
        values[i] = values[child];
        i = child;
      }
      keys[i] = key;
      values[i] = value;
    }
    return top;
  }
}

/** Distance from `p` to the polyline. */
export function distanceToRoute(points: XY[], p: XY): number {
  let best = Infinity;
  for (let i = 1; i < points.length; i++) {
    const a = points[i - 1];
    const b = points[i];
    const dx = b.x - a.x;
    const dy = b.y - a.y;
    const len = dx * dx + dy * dy;
    const t = len ? Math.max(0, Math.min(1, ((p.x - a.x) * dx + (p.y - a.y) * dy) / len)) : 0;
    best = Math.min(best, Math.hypot(p.x - (a.x + t * dx), p.y - (a.y + t * dy)));
  }
  return best;
}

/** Trace the polyline on `ctx` with rounded corners. */
export function traceRoute(ctx: CanvasRenderingContext2D, points: XY[], radius: number): void {
  ctx.moveTo(points[0].x, points[0].y);
  for (let i = 1; i < points.length - 1; i++) {
    const prev = points[i - 1];
    const at = points[i];
    const next = points[i + 1];
    const r = Math.min(
      radius,
      Math.hypot(at.x - prev.x, at.y - prev.y) / 2,
      Math.hypot(next.x - at.x, next.y - at.y) / 2,
    );
    ctx.arcTo(at.x, at.y, next.x, next.y, r);
  }
  const last = points[points.length - 1];
  ctx.lineTo(last.x, last.y);
}
