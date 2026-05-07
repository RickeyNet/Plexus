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
    lower(host.device_type).includes(q)
  );
}

export function filterGroups(
  groups: InventoryGroupFull[],
  query: string,
): InventoryGroupFull[] {
  const q = query.trim().toLowerCase();
  if (!q) return groups;
  return groups.filter((group) => {
    if (
      lower(group.name).includes(q) ||
      lower(group.description).includes(q)
    ) {
      return true;
    }
    return (group.hosts || []).some((host) => hostMatchesQuery(host, q));
  });
}

export function sortGroups(
  groups: InventoryGroupFull[],
  sort: InventorySort,
): InventoryGroupFull[] {
  const copy = groups.slice();
  const hostCount = (g: InventoryGroupFull) =>
    g.host_count ?? (g.hosts || []).length;
  switch (sort) {
    case 'name_asc':
      return copy.sort((a, b) => a.name.localeCompare(b.name));
    case 'name_desc':
      return copy.sort((a, b) => b.name.localeCompare(a.name));
    case 'hosts_asc':
      return copy.sort((a, b) => hostCount(a) - hostCount(b));
    case 'hosts_desc':
      return copy.sort((a, b) => hostCount(b) - hostCount(a));
    case 'custom':
    default:
      return copy;
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
