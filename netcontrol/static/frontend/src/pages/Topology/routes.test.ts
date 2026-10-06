import { describe, expect, it } from 'vitest';

import type { XY } from './layout';
import { distanceToRoute, routeSourceLinks } from './routes';

// Does the vertical or horizontal segment a-b pass within `clear` of p?
function passes(a: XY, b: XY, p: XY, clear: number): boolean {
  return distanceToRoute([a, b], p) < clear;
}

describe('routes between sources', () => {
  // A Cato site of two Sockets, each under its WAN link, beside another
  // Cato site; an AWS VPC level with them far to the right.
  const positions = new Map<string, XY>([
    ['wan-a', { x: 0, y: 290 }],
    ['sock-a', { x: 0, y: 400 }],
    ['wan-b', { x: 120, y: 290 }],
    ['sock-b', { x: 120, y: 400 }],
    ['other-site', { x: 300, y: 400 }],
    ['pop', { x: 60, y: 120 }],
    ['vpc', { x: 3000, y: 400 }],
    ['vpc2', { x: 3200, y: 400 }],
  ]);
  const top = 0;

  it('goes up out of the sources, over and down instead of through the sites between', () => {
    const route = routeSourceLinks([{ id: 'e1', from: 'sock-a', to: 'vpc' }], positions, top).get('e1')!;
    expect(route[0]).toEqual(positions.get('sock-a'));
    expect(route[route.length - 1]).toEqual(positions.get('vpc'));
    const lane = Math.min(...route.map((p) => p.y));
    expect(lane).toBeLessThan(top);
    // Every segment is vertical or horizontal, and none passes another node.
    for (let i = 1; i < route.length; i++) {
      const [a, b] = [route[i - 1], route[i]];
      expect(a.x === b.x || a.y === b.y).toBe(true);
      for (const [id, p] of positions) {
        if (id === 'sock-a' || id === 'vpc') continue;
        expect(passes(a, b, p, 25), `${id} on segment ${i}`).toBe(false);
      }
    }
  });

  it('gives overlapping links lanes of their own, the shorter one lower', () => {
    const routes = routeSourceLinks(
      [
        { id: 'long', from: 'sock-a', to: 'vpc2' },
        { id: 'short', from: 'sock-b', to: 'vpc' },
      ],
      positions,
      top,
    );
    const lane = (id: string) => Math.min(...routes.get(id)!.map((p) => p.y));
    expect(lane('short')).toBeGreaterThan(lane('long'));
  });

  it('rises side by side when one node has two links, not as one line', () => {
    const routes = routeSourceLinks(
      [
        { id: 'one', from: 'sock-a', to: 'vpc' },
        { id: 'two', from: 'sock-a', to: 'vpc2' },
      ],
      positions,
      top,
    );
    // The second point of a route is at the column it rises in.
    expect(Math.abs(routes.get('one')![1].x - routes.get('two')![1].x)).toBeGreaterThanOrEqual(10);
  });

  it('lets links that do not overlap share a lane', () => {
    const apart = new Map<string, XY>([
      ['a', { x: 0, y: 400 }],
      ['b', { x: 500, y: 400 }],
      ['c', { x: 2000, y: 400 }],
      ['d', { x: 2500, y: 400 }],
    ]);
    const routes = routeSourceLinks(
      [
        { id: 'ab', from: 'a', to: 'b' },
        { id: 'cd', from: 'c', to: 'd' },
      ],
      apart,
      top,
    );
    const lane = (id: string) => Math.min(...routes.get(id)!.map((p) => p.y));
    expect(lane('ab')).toBe(lane('cd'));
  });

  it('measures the distance to a route', () => {
    const route = [
      { x: 0, y: 0 },
      { x: 0, y: -100 },
      { x: 200, y: -100 },
    ];
    expect(distanceToRoute(route, { x: 100, y: -95 })).toBe(5);
    expect(distanceToRoute(route, { x: -3, y: -50 })).toBe(3);
  });
});
