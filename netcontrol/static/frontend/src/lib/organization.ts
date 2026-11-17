/**
 * Pure helpers for the location hierarchy and tenancy: site status labels,
 * tree select options (regions, tenant groups), the parents a node may move
 * under, the time zone choices and the rows of a tenant's owned counts.
 */
import { descendantIdsOf } from './tree';

export const SITE_STATUS_LABELS: Record<string, string> = {
  active: 'Active',
  planned: 'Planned',
  staging: 'Staging',
  decommissioning: 'Decommissioning',
  retired: 'Retired',
};

/** Display text for a site status; unknown values pass through. */
export function siteStatusLabel(status: string | null | undefined): string {
  if (!status) return 'Active';
  return SITE_STATUS_LABELS[status] ?? status;
}

/** Badge tone for a site status. */
export function siteStatusTone(status: string | null | undefined): 'success' | 'info' | 'warning' | 'neutral' {
  switch (status) {
    case 'planned':
    case 'staging':
      return 'info';
    case 'decommissioning':
      return 'warning';
    case 'retired':
      return 'neutral';
    default:
      return 'success';
  }
}

export interface TreeOptionNode {
  id: number;
  parent_id: number | null;
  name: string;
  depth: number;
}

export interface TreeOption {
  value: number;
  label: string;
}

/**
 * Select options for a tree listed in tree order, each indented by its
 * depth. With `excludeSubtreeOf`, that node and everything under it are left
 * out: the parents a node may move under without making a cycle.
 */
export function treeOptions(nodes: readonly TreeOptionNode[], excludeSubtreeOf?: number | null): TreeOption[] {
  const excluded = new Set<number>();
  if (excludeSubtreeOf != null) {
    excluded.add(excludeSubtreeOf);
    for (const id of descendantIdsOf([...nodes], (n) => n.id, (n) => n.parent_id, excludeSubtreeOf)) excluded.add(id);
  }
  return nodes
    .filter((n) => !excluded.has(n.id))
    .map((n) => ({ value: n.id, label: `${'  '.repeat(Math.max(0, n.depth))}${n.name}` }));
}

let zonesCache: string[] | null = null;

/** The IANA time zones the browser knows, for the site time zone suggestions. */
export function timeZoneOptions(): string[] {
  if (zonesCache) return zonesCache;
  try {
    zonesCache = Intl.supportedValuesOf('timeZone');
  } catch {
    zonesCache = [];
  }
  return zonesCache;
}

const COUNT_LABELS: Record<string, string> = {
  hosts: 'Hosts',
  sites: 'Sites',
  prefixes: 'Prefixes',
  ip_addresses: 'IP addresses',
  vlans: 'VLANs',
  vrfs: 'VRFs',
};
const COUNT_ORDER = Object.keys(COUNT_LABELS);

/**
 * The rows of a tenant's owned counts: the known kinds first in a fixed
 * order, then any other kind (a later table) by name with its table name
 * made readable (`virtual_machines` -> "Virtual machines").
 */
export function tenantCountRows(counts: Record<string, number> | undefined): { key: string; label: string; count: number }[] {
  const entries = Object.entries(counts ?? {});
  const rank = (k: string) => {
    const i = COUNT_ORDER.indexOf(k);
    return i === -1 ? COUNT_ORDER.length : i;
  };
  return entries
    .sort(([a], [b]) => rank(a) - rank(b) || a.localeCompare(b))
    .map(([key, count]) => ({ key, count, label: COUNT_LABELS[key] ?? readable(key) }));
}

function readable(key: string): string {
  const text = key.replace(/_/g, ' ').trim();
  return text ? text[0].toUpperCase() + text.slice(1) : key;
}
