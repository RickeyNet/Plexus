/**
 * Generic helpers for flat lists that encode a tree through a parent id
 * (inventory groups, graph tree nodes). Callers pass accessors for the id
 * and the parent id so one implementation serves every row shape.
 */

export interface TreeEntry<T> {
  item: T;
  /** 0 for a top-level item, 1 for its children, and so on. */
  depth: number;
}

/**
 * The items in tree order (each parent followed by its children), with the
 * children of each parent sorted by `compare` (stable: ties keep the input
 * order). An item whose parent is not in the list is placed at the top
 * level; items caught in a parent cycle are appended at depth 0 rather than
 * dropped.
 */
export function treeOrder<T>(
  items: T[],
  idOf: (item: T) => number,
  parentOf: (item: T) => number | null | undefined,
  compare: (a: T, b: T) => number = () => 0,
): TreeEntry<T>[] {
  const ids = new Set(items.map(idOf));
  const children = new Map<number | null, T[]>();
  for (const item of items) {
    const p = parentOf(item);
    const parent = p != null && ids.has(p) ? p : null;
    const list = children.get(parent) ?? [];
    list.push(item);
    children.set(parent, list);
  }
  const out: TreeEntry<T>[] = [];
  const seen = new Set<number>();
  const walk = (parent: number | null, depth: number) => {
    for (const item of (children.get(parent) ?? []).slice().sort(compare)) {
      const id = idOf(item);
      if (seen.has(id)) continue;
      seen.add(id);
      out.push({ item, depth });
      walk(id, depth + 1);
    }
  };
  walk(null, 0);
  for (const item of items) {
    if (!seen.has(idOf(item))) out.push({ item, depth: 0 });
  }
  return out;
}

/** The ids of an item's children at any depth (not the item itself). */
export function descendantIdsOf<T>(
  items: T[],
  idOf: (item: T) => number,
  parentOf: (item: T) => number | null | undefined,
  rootId: number,
): Set<number> {
  const children = new Map<number, number[]>();
  for (const item of items) {
    const p = parentOf(item);
    if (p == null) continue;
    children.set(p, [...(children.get(p) ?? []), idOf(item)]);
  }
  const out = new Set<number>();
  const stack = [...(children.get(rootId) ?? [])];
  while (stack.length) {
    const id = stack.pop() as number;
    if (id === rootId || out.has(id)) continue;
    out.add(id);
    stack.push(...(children.get(id) ?? []));
  }
  return out;
}
