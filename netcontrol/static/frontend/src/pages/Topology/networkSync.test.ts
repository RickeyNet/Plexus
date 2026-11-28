import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Edge as VisEdge, Node as VisNode } from 'vis-network';

import { TopologyNetwork, diffItems, itemSignature, seedPosition, withoutPlacement } from './networkSync';

// vis-network needs a canvas; the stand-ins record what the map asks of it.
const vis = vi.hoisted(() => {
  class FakeDataSet<T extends { id?: number | string }> {
    items = new Map<number | string, T>();
    updates: T[][] = [];
    removals: (number | string)[][] = [];
    constructor(items: T[] = []) {
      for (const item of items) this.items.set(item.id!, item);
    }
    update(items: T[]) {
      this.updates.push(items);
      for (const item of items) this.items.set(item.id!, { ...this.items.get(item.id!), ...item });
    }
    remove(ids: (number | string)[]) {
      this.removals.push(ids);
      for (const id of ids) this.items.delete(id);
    }
  }
  class FakeNetwork {
    static built: FakeNetwork[] = [];
    destroyed = false;
    calls: string[] = [];
    constructor(
      public container: unknown,
      public data: { nodes: FakeDataSet<VisNode>; edges: FakeDataSet<VisEdge> },
      public options: unknown,
    ) {
      FakeNetwork.built.push(this);
    }
    destroy() {
      this.destroyed = true;
    }
    // Calls that would move the viewport or the selection.
    fit() { this.calls.push('fit'); }
    moveTo() { this.calls.push('moveTo'); }
    selectNodes() { this.calls.push('selectNodes'); }
    unselectAll() { this.calls.push('unselectAll'); }
    setData() { this.calls.push('setData'); }
    stabilize() { this.calls.push('stabilize'); }
  }
  return { FakeDataSet, FakeNetwork };
});

vi.mock('vis-network/standalone', () => ({ DataSet: vis.FakeDataSet, Network: vis.FakeNetwork }));

type Fake = InstanceType<typeof vis.FakeNetwork>;

const node = (id: number | string, extra: Partial<VisNode> = {}): VisNode => ({ id, label: `node-${id}`, ...extra });
const edge = (id: number | string, from: number | string, to: number | string, extra: Partial<VisEdge> = {}): VisEdge => ({
  id,
  from,
  to,
  ...extra,
});

function signatures<T extends { id?: number | string }>(items: T[]) {
  return new Map(items.map((item) => [item.id!, itemSignature(item)]));
}

describe('diffItems', () => {
  it('sorts items into added, changed and removed, leaving unchanged ones out', () => {
    const before = [node(1), node(2), node(3), node(4)];
    const after = [node(5), node(2, { label: 'renamed' }), node(1), node(6)];
    const diff = diffItems(signatures(before), after);
    expect(diff.add.map((n) => n.id)).toEqual([5, 6]);
    expect(diff.update).toEqual([{ id: 2, label: 'renamed' }]);
    expect(diff.remove).toEqual([3, 4]);
    expect([...diff.signatures.keys()]).toEqual([5, 2, 1, 6]);
  });

  it('keeps the given order and the drawn order for removals', () => {
    const before = [node('b'), node('a'), node('d'), node('c')];
    const after = [node('c', { label: 'x' }), node('a', { label: 'y' }), node('e'), node('f')];
    const diff = diffItems(signatures(before), after);
    expect(diff.update.map((n) => n.id)).toEqual(['c', 'a']);
    expect(diff.add.map((n) => n.id)).toEqual(['e', 'f']);
    expect(diff.remove).toEqual(['b', 'd']);
  });

  it('does not count a move as a change, and never sends a drawn node its placement', () => {
    const before = [node(1, { x: 0, y: 0, fixed: { x: true, y: true }, physics: false })];
    expect(diffItems(signatures(before), [node(1, { x: 500, y: -20 })]).update).toEqual([]);
    const changed = diffItems(signatures(before), [node(1, { x: 500, y: -20, color: '#123456' })]);
    expect(changed.update).toEqual([{ id: 1, label: 'node-1', color: '#123456' }]);
  });

  it('adds a new node whole, placement included', () => {
    const diff = diffItems(new Map(), [node(9, { x: 10, y: 20, physics: false })]);
    expect(diff.add).toEqual([{ id: 9, label: 'node-9', x: 10, y: 20, physics: false }]);
  });

  it('treats an edge with the same id and other ends as changed, and a new id as new', () => {
    const before = [edge('e1', 1, 2), edge('e2', 2, 3)];
    const diff = diffItems(signatures(before), [edge('e1', 1, 4), edge('e2', 2, 3), edge('e3', 2, 3)]);
    expect(diff.update).toEqual([{ id: 'e1', from: 1, to: 4 }]);
    expect(diff.add.map((e) => e.id)).toEqual(['e3']);
    expect(diff.remove).toEqual([]);
  });

  it('keeps numeric and string ids apart and skips duplicates and items without an id', () => {
    const diff = diffItems(signatures([node(1)]), [node('1'), node(1), node(1, { label: 'dup' }), { label: 'no id' }]);
    expect(diff.add.map((n) => n.id)).toEqual(['1']);
    expect(diff.update).toEqual([]);
    expect(diff.remove).toEqual([]);
  });

  it('withoutPlacement leaves the item it is given alone', () => {
    const item = node(1, { x: 1, y: 2, fixed: true, physics: true });
    expect(withoutPlacement(item)).toEqual({ id: 1, label: 'node-1' });
    expect(item.x).toBe(1);
  });
});

describe('seedPosition', () => {
  it('starts a new node next to the middle of its placed neighbours', () => {
    const at = seedPosition([{ x: 0, y: 0 }, { x: 200, y: 100 }], 0, 90);
    expect(at).toEqual({ x: 190, y: 50 });
  });

  it('spreads several new nodes at one place', () => {
    const spots = [0, 1, 2, 3].map((i) => seedPosition([{ x: 0, y: 0 }], i));
    expect(new Set(spots.map((p) => `${p?.x},${p?.y}`)).size).toBe(4);
  });

  it('has no place for a node without a placed neighbour', () => {
    expect(seedPosition([])).toBeNull();
  });
});

describe('TopologyNetwork', () => {
  const container = {} as HTMLElement;
  const options = () => ({});

  beforeEach(() => {
    vis.FakeNetwork.built = [];
  });

  function built(): Fake[] {
    return vis.FakeNetwork.built;
  }

  it('builds one instance and diffs a refresh into its DataSets', () => {
    const map = new TopologyNetwork();
    expect(map.show(container, 'all|tidy', [node(1), node(2)], [edge('e1', 1, 2)], options)).toBe(true);
    const network = built()[0];
    const nodes = network.data.nodes;
    const edges = network.data.edges;

    const created = map.show(
      container,
      'all|tidy',
      [node(1, { color: '#ff0000' }), node(2), node(3, { x: 5, y: 6 })],
      [edge('e1', 1, 2), edge('e2', 2, 3)],
      options,
    );

    expect(created).toBe(false);
    expect(built()).toHaveLength(1);
    expect(network.destroyed).toBe(false);
    expect(map.current?.network).toBe(network);
    // Only the changed and the new items are sent; the unchanged node 2 is not.
    expect(nodes.updates).toEqual([[node(3, { x: 5, y: 6 }), node(1, { color: '#ff0000' })]]);
    expect(edges.updates).toEqual([[edge('e2', 2, 3)]]);
    expect(nodes.removals).toEqual([]);
    // Nothing that would move the viewport, drop the selection or re-run a layout.
    expect(network.calls).toEqual([]);
  });

  it('removes what a refresh no longer has, edges before nodes', () => {
    const map = new TopologyNetwork();
    map.show(container, 'all|tidy', [node(1), node(2), node(3)], [edge('e1', 1, 2), edge('e2', 2, 3)], options);
    const network = built()[0];
    map.show(container, 'all|tidy', [node(1), node(2)], [edge('e1', 1, 2)], options);
    expect(network.data.edges.removals).toEqual([['e2']]);
    expect(network.data.nodes.removals).toEqual([[3]]);
    expect(network.data.nodes.updates).toEqual([]);
    expect(map.hasNode(3)).toBe(false);
    expect(map.hasNode(2)).toBe(true);
  });

  it('sends nothing for a refresh that changes nothing', () => {
    const map = new TopologyNetwork();
    map.show(container, 'all|tidy', [node(1)], [], options);
    map.show(container, 'all|tidy', [node(1, { x: 40, y: 40 })], [], options);
    const network = built()[0];
    expect(network.data.nodes.updates).toEqual([]);
    expect(network.data.edges.updates).toEqual([]);
  });

  it('builds a new instance when the layout or the group changes, destroying the old one', () => {
    const map = new TopologyNetwork();
    map.show(container, 'all|tidy', [node(1)], [], options);
    expect(map.show(container, 'all|physics', [node(1)], [], options)).toBe(true);
    expect(map.show(container, '7|physics', [node(1)], [], options)).toBe(true);
    expect(built()).toHaveLength(3);
    expect(built().map((n) => n.destroyed)).toEqual([true, true, false]);
    // The new instance gets every item whole.
    expect([...built()[2].data.nodes.items.keys()]).toEqual([1]);
  });

  it('builds a new instance for a new container', () => {
    const map = new TopologyNetwork();
    map.show(container, 'all|tidy', [node(1)], [], options);
    expect(map.show({} as HTMLElement, 'all|tidy', [node(1)], [], options)).toBe(true);
    expect(built()[0].destroyed).toBe(true);
  });

  it('destroys the instance on unmount and starts afresh after', () => {
    const map = new TopologyNetwork();
    map.show(container, 'all|tidy', [node(1)], [], options);
    map.destroy();
    expect(built()[0].destroyed).toBe(true);
    expect(map.current).toBeNull();
    expect(map.hasNode(1)).toBe(false);
    expect(map.keeps(container, 'all|tidy')).toBe(false);
    expect(map.show(container, 'all|tidy', [node(1)], [], options)).toBe(true);
    expect(built()).toHaveLength(2);
  });

  it('asks for the options only when it builds', () => {
    const map = new TopologyNetwork();
    const make = vi.fn(() => ({ physics: { enabled: false } }));
    map.show(container, 'all|tidy', [node(1)], [], make);
    map.show(container, 'all|tidy', [node(1), node(2)], [], make);
    expect(make).toHaveBeenCalledTimes(1);
    expect(built()[0].options).toEqual({ physics: { enabled: false } });
  });
});
