/**
 * Pure helpers for the Topology page's bulk "Add to inventory" dialog: which
 * map nodes can be added, the device type and inventory group each is likely
 * to belong in, and the request body for POST /api/inventory/hosts/bulk.
 */
import { GROUP_PATH_SEPARATOR, type BulkAddHostsRequest } from '@/api/inventory';
import type { TopologyEdge, TopologyNode } from '@/api/topology';
import { DEFAULT_DEVICE_TYPE, DEVICE_TYPES } from '@/lib/deviceTypes';

import { providerLabel } from './helpers';

type DeviceTypeList = readonly { value: string }[];

/** One device of the dialog: a map node that is not an inventory host. */
export interface InventoryAddRow {
  /** The node's address; also the row key (rows are deduplicated by IP). */
  ip: string;
  nodeId: number | string;
  label: string;
  /** Model or platform string the map reported. */
  platform: string;
  /** Meraki/cloud site, or the inventory group the node was seen in. */
  site: string;
  /** Suggested inventory group, as the names from the top (see `suggestGroupPath`). */
  groupPath: string[];
  /** `groupPath` joined with " / ": its display text, and the key renames use. */
  group: string;
  /** Suggested device type (a key of DEVICE_TYPES). */
  deviceType: string;
  /** A cloud-managed device (Meraki hardware) with no CLI to SSH to. */
  managed: boolean;
}

/** The integrations whose own devices are cloud-managed and have no CLI. */
const MANAGED_PROVIDERS = new Set(['meraki']);

/**
 * The longest inventory group name the dialog suggests. The database sets no
 * limit; this keeps generated names readable.
 */
export const GROUP_NAME_MAX = 120;

/** The group of devices that belong to no site and no inventory group. */
export const DEFAULT_ADD_GROUP = 'Topology devices';

/** The parent group of SNMP neighbors, with a sub-group per reporting group. */
export const DISCOVERED_NEIGHBORS_GROUP = 'Discovered neighbors';

/** A group name trimmed, with whitespace collapsed, capped at GROUP_NAME_MAX. */
export function normalizeGroupName(name: string): string {
  return name.replace(/\s+/g, ' ').trim().slice(0, GROUP_NAME_MAX).trim();
}

/**
 * The inventory group a map node is suggested to go into, as the names from
 * the top group down, from what the node is associated with:
 * 1. a snapshot site (Meraki network, Cato site, FMC/Panorama/Appgate site,
 *    AWS VPC, Azure VNet, GCP network): `[<Provider>, <site>]`. A CDP/LLDP
 *    neighbor a Meraki device reported carries that device's site, so it
 *    lands there;
 * 2. an inventory group (an SNMP neighbor of an inventory host):
 *    `["Discovered neighbors", <group>]`;
 * 3. otherwise `[DEFAULT_ADD_GROUP]`.
 */
export function suggestGroupPath(node: Pick<TopologyNode, 'meraki' | 'source' | 'group_name'>): string[] {
  const site = normalizeGroupName(node.meraki?.site_name ?? '');
  if (site) return [normalizeGroupName(providerLabel(node.meraki?.provider ?? node.source)), site];
  const group = normalizeGroupName(node.group_name ?? '');
  if (group) return [DISCOVERED_NEIGHBORS_GROUP, group];
  return [DEFAULT_ADD_GROUP];
}

// Ordered: the first rule that matches the node's model/platform text wins.
// Each rule names the device types to try, best first.
const RULES: readonly { test: RegExp; types: readonly string[] }[] = [
  { test: /nx-?os|nexus/i, types: ['cisco_nxos'] },
  { test: /\bftd\b|firepower|threat defense/i, types: ['cisco_ftd'] },
  { test: /\basa\d*\b|adaptive security/i, types: ['cisco_asa'] },
  { test: /ios[- ]?xr/i, types: ['cisco_xr'] },
  { test: /ios[- ]?xe/i, types: ['cisco_xe', 'cisco_ios'] },
  { test: /(^|[^a-z0-9])(ws-)?c[39]\d{3}|catalyst|\bios\b/i, types: ['cisco_xe', 'cisco_ios'] },
  { test: /arista|\beos\b/i, types: ['arista_eos'] },
  { test: /juniper|junos/i, types: ['juniper_junos'] },
  { test: /forti/i, types: ['fortinet'] },
  { test: /palo ?alto|pan-?os/i, types: ['paloalto_panos'] },
  { test: /aos-?cx|aruba.*\bcx\b/i, types: ['aruba_aoscx'] },
  { test: /aruba|procurve|\baos-?s(witch)?\b/i, types: ['aruba_osswitch', 'aruba_aoscx'] },
];

/**
 * The device type a map node most likely is, from its model and platform
 * (`cisco C9410R` is IOS-XE, `Cisco NX-OS` is NX-OS, …). A node whose text
 * names no known platform (Linux, a phone, a Meraki device) is ICMP-only.
 * Only keys of `types` are returned.
 */
export function guessDeviceType(
  node: Pick<TopologyNode, 'model' | 'platform' | 'device_type'>,
  types: DeviceTypeList = DEVICE_TYPES,
): string {
  const known = new Set(types.map((t) => t.value));
  const fallback = known.has('icmp_only') ? 'icmp_only' : DEFAULT_DEVICE_TYPE;
  // A node that already carries a real driver key keeps it.
  if (node.device_type && node.device_type !== 'icmp_only' && known.has(node.device_type)) {
    return node.device_type;
  }
  const text = [node.model, node.platform].filter(Boolean).join(' ');
  if (!text) return fallback;
  for (const rule of RULES) {
    if (!rule.test.test(text)) continue;
    return rule.types.find((t) => known.has(t)) ?? fallback;
  }
  return fallback;
}

/**
 * The inventory group of the host that reported each SNMP neighbor: for
 * every node linked to an inventory host, that host's `group_name` (the
 * first such link wins).
 */
function reportingGroups(nodes: readonly TopologyNode[], edges: readonly TopologyEdge[]): Map<string, string> {
  const hostGroup = new Map<string, string>();
  for (const n of nodes) {
    if (n.in_inventory && n.group_name) hostGroup.set(String(n.id), n.group_name);
  }
  const out = new Map<string, string>();
  for (const e of edges) {
    for (const [self, other] of [[e.to, e.from], [e.from, e.to]] as const) {
      const group = hostGroup.get(String(other));
      if (group && !out.has(String(self))) out.set(String(self), group);
    }
  }
  return out;
}

/**
 * The dialog's rows: every node not in inventory that has an IP, one per
 * address (the same CDP/LLDP neighbor is often reported by several devices;
 * the first label wins), sorted by label. Cloud-managed devices (Meraki
 * hardware, which has no CLI) are left out unless `includeManaged`. `edges`
 * name the inventory host that reported an SNMP neighbor, whose group the
 * neighbor's suggested group is named after.
 */
export function buildInventoryAddRows(
  nodes: readonly TopologyNode[],
  types: DeviceTypeList = DEVICE_TYPES,
  includeManaged = false,
  edges: readonly TopologyEdge[] = [],
): InventoryAddRow[] {
  const reporters = edges.length ? reportingGroups(nodes, edges) : new Map<string, string>();
  const byIp = new Map<string, InventoryAddRow>();
  for (const node of nodes) {
    const ip = (node.ip ?? '').trim();
    if (node.in_inventory || !ip || byIp.has(ip)) continue;
    // Every snapshot device has source 'meraki'; the integration is meraki.provider.
    const managed = node.source === 'meraki' && MANAGED_PROVIDERS.has(node.meraki?.provider ?? 'meraki');
    if (managed && !includeManaged) continue;
    const groupName = node.group_name || reporters.get(String(node.id)) || '';
    const groupPath = suggestGroupPath({ ...node, group_name: groupName });
    byIp.set(ip, {
      ip,
      nodeId: node.id,
      label: node.label || ip,
      platform: node.model || node.platform || '',
      site: node.meraki?.site_name || groupName,
      groupPath,
      group: groupPath.join(GROUP_PATH_SEPARATOR),
      deviceType: guessDeviceType(node, types),
      managed,
    });
  }
  return [...byIp.values()].sort((a, b) => a.label.localeCompare(b.label) || a.ip.localeCompare(b.ip));
}

/** Rows whose label, IP, platform, site or group contains the query (case-insensitive). */
export function filterInventoryAddRows(rows: readonly InventoryAddRow[], query: string): InventoryAddRow[] {
  const q = query.trim().toLowerCase();
  if (!q) return [...rows];
  return rows.filter((r) => [r.label, r.ip, r.platform, r.site, r.group].some((v) => v.toLowerCase().includes(q)));
}

/**
 * Where the dialog adds the selected devices: each to its suggested group
 * (`renames` maps a suggestion's display path to the name the user gave its
 * leaf, the sub-group), or all to one existing group.
 */
export type BulkAddGrouping =
  | { mode: 'auto'; renames?: Readonly<Record<string, string>> }
  | { mode: 'single'; groupId: number };

/**
 * The group path a row goes into in automatic mode, after the user's
 * renames: a rename replaces the leaf; the parents stay.
 */
export function resolvedGroupPath(row: InventoryAddRow, renames: Readonly<Record<string, string>> = {}): string[] {
  const leaf = normalizeGroupName(renames[row.group] ?? '') || row.groupPath[row.groupPath.length - 1];
  return [...row.groupPath.slice(0, -1), leaf];
}

/**
 * The groups automatic mode will use for the selected rows, with how many
 * rows go into each, in first-seen order. Keyed by the suggestion's display
 * path, so the dialog can rename each one's leaf.
 */
export function suggestedGroups(
  rows: readonly InventoryAddRow[],
  selected: ReadonlySet<string>,
): { group: string; path: string[]; count: number }[] {
  const byGroup = new Map<string, { group: string; path: string[]; count: number }>();
  for (const r of rows) {
    if (!selected.has(r.ip)) continue;
    const entry = byGroup.get(r.group);
    if (entry) entry.count += 1;
    else byGroup.set(r.group, { group: r.group, path: r.groupPath, count: 1 });
  }
  return [...byGroup.values()];
}

/**
 * The bulk-add body for the selected rows, in row order. `deviceTypes`
 * holds the per-row choices the user changed (by IP); other rows keep their
 * suggested type. In automatic mode each host names its group path (the
 * backend creates each missing level); in single mode the body names the one
 * group.
 */
export function buildBulkAddBody(
  rows: readonly InventoryAddRow[],
  selected: ReadonlySet<string>,
  deviceTypes: Readonly<Record<string, string>>,
  grouping: BulkAddGrouping,
): BulkAddHostsRequest {
  const hosts = rows
    .filter((r) => selected.has(r.ip))
    .map((r) => ({
      hostname: r.label,
      ip_address: r.ip,
      device_type: deviceTypes[r.ip] ?? r.deviceType,
      ...(grouping.mode === 'auto' ? { group_path: resolvedGroupPath(r, grouping.renames) } : {}),
    }));
  return grouping.mode === 'single' ? { group_id: grouping.groupId, hosts } : { hosts };
}
