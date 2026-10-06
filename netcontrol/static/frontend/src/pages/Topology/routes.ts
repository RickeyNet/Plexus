/**
 * Routes for the links between two sources of the tidy layout (a Cato
 * vSocket and its AWS VPC, a vMX and its VPC...).
 *
 * Drawn as vis draws every other link, such a link would run straight
 * across the sites of its own source and of every source between the two.
 * Instead it goes up from each end, clear of the nodes above it, to a lane
 * above the top of every source, and across: up, out of the source's frame,
 * over and down. Links whose stretches of lane overlap get lanes of their
 * own, the shortest lowest, so they nest instead of crossing.
 */

import type { XY } from './layout';

type NodeId = number | string;

export interface SourceLink {
  id: NodeId;
  from: NodeId;
  to: NodeId;
}

// The lowest lane, above the top of the sources (and their titles).
const LANE_ABOVE = 70;
const LANE_STEP = 18;
// Stretches of lane closer than this share no lane.
const LANE_MARGIN = 24;
// A route keeps this far from the centre of any other node.
const NODE_CLEAR = 30;
// The column a route rises in, tried at these steps beside its node.
const RISE_STEP = 20;
const RISE_TRIES = 10;
// Two rises closer than this would draw as one line.
const RISE_CLEAR = 10;

interface Rise {
  x: number;
  top: number;
  bottom: number;
}

/**
 * The polyline of each link, from its `from` node to its `to` node.
 * `top` is the top of the highest source frame.
 */
export function routeSourceLinks(links: SourceLink[], positions: Map<NodeId, XY>, top: number): Map<NodeId, XY[]> {
  const routes = new Map<NodeId, XY[]>();
  const placed = links.filter((l) => positions.has(l.from) && positions.has(l.to) && l.from !== l.to);
  if (!placed.length) return routes;
  const nodes = [...positions];
  const rises: Rise[] = [];
  const base = top - LANE_ABOVE;

  // The column beside `id` it rises in to `laneY`: the nearest one that no
  // other node and no other route is in the way of, leaning towards `toward`.
  function riseX(id: NodeId, laneY: number, toward: number): number {
    const at = positions.get(id)!;
    const lean = toward >= at.x ? 1 : -1;
    let best = at.x;
    let bestHits = Infinity;
    for (let step = 0; step <= RISE_TRIES * 2; step++) {
      const offset = step === 0 ? 0 : Math.ceil(step / 2) * RISE_STEP * (step % 2 ? lean : -lean);
      const x = at.x + offset;
      let hits = 0;
      for (const [other, p] of nodes) {
        if (other === id) continue;
        // In the way of the rise, or of the step aside to it.
        const inRise = Math.abs(p.x - x) < NODE_CLEAR && p.y < at.y && p.y > laneY;
        const inStep =
          offset !== 0 && Math.abs(p.y - at.y) < NODE_CLEAR && p.x > Math.min(at.x, x) - NODE_CLEAR && p.x < Math.max(at.x, x) + NODE_CLEAR;
        if (inRise || inStep) hits++;
      }
      for (const r of rises) {
        if (Math.abs(r.x - x) < RISE_CLEAR && r.top < at.y && r.bottom > laneY) hits++;
      }
      if (hits < bestHits) {
        best = x;
        bestHits = hits;
        if (!hits) break;
      }
    }
    return best;
  }

  // Lanes: each link spans the stretch between its ends; the shortest go lowest.
  const spans = placed
    .map((l) => {
      const a = positions.get(l.from)!;
      const b = positions.get(l.to)!;
      return { link: l, x0: Math.min(a.x, b.x), x1: Math.max(a.x, b.x) };
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
    const { from, to } = span.link;
    const a = positions.get(from)!;
    const b = positions.get(to)!;
    const ax = riseX(from, laneY, b.x);
    rises.push({ x: ax, top: laneY, bottom: a.y });
    const bx = riseX(to, laneY, a.x);
    rises.push({ x: bx, top: laneY, bottom: b.y });
    const points: XY[] = [a];
    if (ax !== a.x) points.push({ x: ax, y: a.y });
    points.push({ x: ax, y: laneY }, { x: bx, y: laneY });
    if (bx !== b.x) points.push({ x: bx, y: b.y });
    points.push(b);
    routes.set(span.link.id, points);
  }
  return routes;
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
