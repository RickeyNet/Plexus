/**
 * Keeps one vis-network instance per map view and applies data refreshes to
 * its DataSets as a diff, so a refresh does not throw away the viewport, the
 * selection, dragged positions or a stabilised layout.
 */
import { DataSet, Network } from 'vis-network/standalone';
import type { Edge as VisEdge, Node as VisNode, Options } from 'vis-network';

import type { XY } from './layout';

export type ItemId = number | string;

// Fields that place a node rather than style it. A refresh leaves them alone
// on a node already drawn: it stays where physics, a layout or a drag put it.
const PLACEMENT_KEYS = ['x', 'y', 'fixed', 'physics'] as const;

/** `item` without the fields that place it on the canvas. */
export function withoutPlacement<T extends object>(item: T): T {
  const rest = { ...(item as Record<string, unknown>) };
  for (const key of PLACEMENT_KEYS) delete rest[key];
  return rest as T;
}

/** What an item looks like, as a string: equal strings draw the same item. */
export function itemSignature(item: object): string {
  return JSON.stringify(withoutPlacement(item));
}

export interface ItemDiff<T> {
  /** Items not drawn yet, whole (placement included), in the order given. */
  add: T[];
  /** Drawn items whose look changed, without their placement, in the order given. */
  update: T[];
  /** Ids drawn before and no longer given, in the order they were drawn. */
  remove: ItemId[];
  /** The signature of every item given, by id: the next diff's `previous`. */
  signatures: Map<ItemId, string>;
}

/**
 * The changes that turn the items drawn (`previous`: their signatures by id)
 * into `next`. An item whose signature is unchanged is left out. An item
 * without an id is skipped, and of two with one id the first counts.
 */
export function diffItems<T extends { id?: ItemId }>(
  previous: ReadonlyMap<ItemId, string>,
  next: readonly T[],
): ItemDiff<T> {
  const add: T[] = [];
  const update: T[] = [];
  const signatures = new Map<ItemId, string>();
  for (const item of next) {
    const id = item.id;
    if (id == null || signatures.has(id)) continue;
    const signature = itemSignature(item);
    signatures.set(id, signature);
    const before = previous.get(id);
    if (before === undefined) add.push(item);
    else if (before !== signature) update.push(withoutPlacement(item));
  }
  const remove = [...previous.keys()].filter((id) => !signatures.has(id));
  return { add, update, remove, signatures };
}

/** The part of a vis DataSet a diff is applied to. */
export interface DataSetLike<T> {
  update(items: T[]): unknown;
  remove(ids: ItemId[]): unknown;
}

// Added and changed items go in one update: DataSet.update adds an id it does
// not hold, so an item some overlay pass wrote early cannot make an add throw.
function applyUpserts<T>(set: DataSetLike<T>, diff: ItemDiff<T>) {
  const upserts = [...diff.add, ...diff.update];
  if (upserts.length) set.update(upserts);
}

/**
 * Where to put a node added to a map that is already drawn: around its
 * neighbours already placed, `ordinal` steps round a circle so several new
 * nodes at one place do not land on each other. Null without a placed neighbour.
 */
export function seedPosition(neighbours: readonly XY[], ordinal = 0, radius = 90): XY | null {
  if (!neighbours.length) return null;
  const cx = neighbours.reduce((sum, p) => sum + p.x, 0) / neighbours.length;
  const cy = neighbours.reduce((sum, p) => sum + p.y, 0) / neighbours.length;
  // The golden angle spreads any number of steps evenly.
  const angle = ordinal * 2.399963229728653;
  return { x: Math.round(cx + radius * Math.cos(angle)), y: Math.round(cy + radius * Math.sin(angle)) };
}

export interface NetworkParts {
  network: Network;
  nodes: DataSet<VisNode>;
  edges: DataSet<VisEdge>;
}

/**
 * The map's vis-network instance. `show` builds one for a new view key (the
 * inputs that decide the layout) and otherwise diffs into the DataSets the
 * instance already draws.
 */
export class TopologyNetwork {
  private parts: NetworkParts | null = null;
  private key: string | null = null;
  private container: HTMLElement | null = null;
  private nodeSignatures = new Map<ItemId, string>();
  private edgeSignatures = new Map<ItemId, string>();

  /** The instance and its DataSets, or null when nothing is drawn. */
  get current(): NetworkParts | null {
    return this.parts;
  }

  /** Whether `show` with this container and key keeps the instance. */
  keeps(container: HTMLElement, key: string): boolean {
    return this.parts !== null && this.container === container && this.key === key;
  }

  /** Whether `id` is a node drawn now. */
  hasNode(id: ItemId): boolean {
    return this.nodeSignatures.has(id);
  }

  /**
   * Draw `nodes` and `edges`. Returns true when a new instance was built (the
   * caller binds its events and fits the view), false when the existing one
   * took the changes.
   */
  show(
    container: HTMLElement,
    key: string,
    nodes: VisNode[],
    edges: VisEdge[],
    options: () => Options,
  ): boolean {
    if (this.parts && this.keeps(container, key)) {
      const nodeDiff = diffItems(this.nodeSignatures, nodes);
      const edgeDiff = diffItems(this.edgeSignatures, edges);
      if (edgeDiff.remove.length) this.parts.edges.remove(edgeDiff.remove);
      if (nodeDiff.remove.length) this.parts.nodes.remove(nodeDiff.remove);
      applyUpserts(this.parts.nodes, nodeDiff);
      applyUpserts(this.parts.edges, edgeDiff);
      this.nodeSignatures = nodeDiff.signatures;
      this.edgeSignatures = edgeDiff.signatures;
      return false;
    }
    this.destroy();
    const nodeDiff = diffItems(new Map(), nodes);
    const edgeDiff = diffItems(new Map(), edges);
    const nodeSet = new DataSet<VisNode>(nodeDiff.add);
    const edgeSet = new DataSet<VisEdge>(edgeDiff.add);
    const network = new Network(container, { nodes: nodeSet, edges: edgeSet }, options());
    this.parts = { network, nodes: nodeSet, edges: edgeSet };
    this.key = key;
    this.container = container;
    this.nodeSignatures = nodeDiff.signatures;
    this.edgeSignatures = edgeDiff.signatures;
    return true;
  }

  /** Destroy the instance (its event listeners go with it). */
  destroy(): void {
    this.parts?.network.destroy();
    this.parts = null;
    this.key = null;
    this.container = null;
    this.nodeSignatures = new Map();
    this.edgeSignatures = new Map();
  }
}
