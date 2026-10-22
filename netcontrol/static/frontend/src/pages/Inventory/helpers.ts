import type { InventoryGroupFull, InventoryHost } from '@/api/inventory';

export type InventorySort =
  | 'custom'
  | 'name_asc'
  | 'name_desc'
  | 'hosts_asc'
  | 'hosts_desc';

const lower = (v: unknown) => String(v ?? '').toLowerCase();

export function hostMatchesQuery(host: InventoryHost, query: string): boolean {
  if (!query) return false;
  const q = query.toLowerCase();
  return (
    lower(host.hostname).includes(q) ||
    lower(host.ip_address).includes(q) ||
    lower(host.device_type).includes(q) ||
    lower(host.aws_instance_id).includes(q)
  );
}

// AWS issues 8 or 17 hex digits; the demo account's IDs are shorter.
const AWS_INSTANCE_ID_RE = /^i-[0-9a-f]{1,17}$/i;

/**
 * Whether `value` looks like an EC2 instance ID (`i-` plus up to 17 hex
 * digits, case-insensitive). Mirrors the backend validation; callers trim first.
 */
export function isAwsInstanceId(value: string): boolean {
  return AWS_INSTANCE_ID_RE.test(value);
}

/**
 * Groups that match the query (name, path, description or a host), plus the
 * ancestors of each match so a matching sub-group still shows under its
 * parent.
 */
export function filterGroups(
  groups: InventoryGroupFull[],
  query: string,
): InventoryGroupFull[] {
  const q = query.trim().toLowerCase();
  if (!q) return groups;
  const matches = (group: InventoryGroupFull) =>
    lower(group.name).includes(q) ||
    lower(group.path).includes(q) ||
    lower(group.description).includes(q) ||
    (group.hosts || []).some((host) => hostMatchesQuery(host, q));
  const parentOf = new Map(groups.map((g) => [g.id, g.parent_id ?? null]));
  const keep = new Set<number>();
  for (const group of groups) {
    if (!matches(group)) continue;
    for (let id: number | null = group.id; id != null && !keep.has(id); id = parentOf.get(id) ?? null) {
      keep.add(id);
    }
  }
  return groups.filter((g) => keep.has(g.id));
}

/**
 * The groups in tree order (each parent followed by its sub-groups), with
 * the sub-groups of each parent sorted by `compare` (stable: ties keep the
 * input order). A group whose parent is not in the list is placed at the
 * top level.
 */
export function treeSort(
  groups: InventoryGroupFull[],
  compare: (a: InventoryGroupFull, b: InventoryGroupFull) => number = () => 0,
): InventoryGroupFull[] {
  const ids = new Set(groups.map((g) => g.id));
  const children = new Map<number | null, InventoryGroupFull[]>();
  for (const g of groups) {
    const parent = g.parent_id != null && ids.has(g.parent_id) ? g.parent_id : null;
    const list = children.get(parent) ?? [];
    list.push(g);
    children.set(parent, list);
  }
  const out: InventoryGroupFull[] = [];
  const seen = new Set<number>();
  const walk = (parent: number | null) => {
    for (const g of (children.get(parent) ?? []).slice().sort(compare)) {
      if (seen.has(g.id)) continue;
      seen.add(g.id);
      out.push(g);
      walk(g.id);
    }
  };
  walk(null);
  // Only a parent cycle leaves groups unvisited; list them rather than drop them.
  return out.concat(groups.filter((g) => !seen.has(g.id)));
}

/** The groups in tree order, siblings by the user's saved order (`orderedIds`). */
export function applyGroupOrder(groups: InventoryGroupFull[], orderedIds: number[]): InventoryGroupFull[] {
  const position = new Map(orderedIds.map((id, i) => [id, i]));
  const rank = (g: InventoryGroupFull) => position.get(g.id) ?? Number.MAX_SAFE_INTEGER;
  return treeSort(groups, (a, b) => rank(a) - rank(b));
}

/** The ids of a group's sub-groups at any depth (not the group itself). */
export function descendantIds(groups: InventoryGroupFull[], groupId: number): Set<number> {
  const children = new Map<number, number[]>();
  for (const g of groups) {
    if (g.parent_id == null) continue;
    children.set(g.parent_id, [...(children.get(g.parent_id) ?? []), g.id]);
  }
  const out = new Set<number>();
  const stack = [...(children.get(groupId) ?? [])];
  while (stack.length) {
    const id = stack.pop() as number;
    if (id === groupId || out.has(id)) continue;
    out.add(id);
    stack.push(...(children.get(id) ?? []));
  }
  return out;
}

/** Groups below a collapsed ancestor, which the page hides. */
export function hiddenByCollapsedAncestor(groups: InventoryGroupFull[], collapsed: Set<number>): Set<number> {
  const parentOf = new Map(groups.map((g) => [g.id, g.parent_id ?? null]));
  const hidden = new Set<number>();
  for (const g of groups) {
    const seen = new Set<number>([g.id]);
    for (let id = parentOf.get(g.id) ?? null; id != null && !seen.has(id); id = parentOf.get(id) ?? null) {
      seen.add(id);
      if (collapsed.has(id)) {
        hidden.add(g.id);
        break;
      }
    }
  }
  return hidden;
}

/** The groups sorted among siblings, keeping the tree (see `treeSort`). */
export function sortGroups(
  groups: InventoryGroupFull[],
  sort: InventorySort,
): InventoryGroupFull[] {
  const hostCount = (g: InventoryGroupFull) =>
    g.host_count ?? (g.hosts || []).length;
  switch (sort) {
    case 'name_asc':
      return treeSort(groups, (a, b) => a.name.localeCompare(b.name));
    case 'name_desc':
      return treeSort(groups, (a, b) => b.name.localeCompare(a.name));
    case 'hosts_asc':
      return treeSort(groups, (a, b) => hostCount(a) - hostCount(b));
    case 'hosts_desc':
      return treeSort(groups, (a, b) => hostCount(b) - hostCount(a));
    case 'custom':
    default:
      return treeSort(groups);
  }
}

/**
 * When a search query is active, hosts that match are bubbled to the top of
 * each group so they're visible without scrolling.
 */
export function sortHostsForQuery(
  hosts: InventoryHost[],
  query: string,
): InventoryHost[] {
  if (!query) return hosts;
  return hosts
    .slice()
    .sort(
      (a, b) =>
        (hostMatchesQuery(b, query) ? 1 : 0) -
        (hostMatchesQuery(a, query) ? 1 : 0),
    );
}

export const COLLAPSED_KEY = 'plexus.inventory.collapsedGroups';
export const COMPACT_KEY = 'plexus.inventory.compact';

export function loadCollapsedSet(): Set<number> {
  try {
    const raw = localStorage.getItem(COLLAPSED_KEY);
    if (!raw) return new Set();
    return new Set((JSON.parse(raw) as unknown[]).map((v) => Number(v)));
  } catch {
    return new Set();
  }
}

export function saveCollapsedSet(set: Set<number>): void {
  try {
    localStorage.setItem(COLLAPSED_KEY, JSON.stringify(Array.from(set)));
  } catch {
    // ignore
  }
}

export function loadCompactMode(): boolean {
  try {
    return localStorage.getItem(COMPACT_KEY) === '1';
  } catch {
    return false;
  }
}

export function saveCompactMode(on: boolean): void {
  try {
    localStorage.setItem(COMPACT_KEY, on ? '1' : '0');
  } catch {
    // ignore
  }
}
