import type {
  DiscoveredHost,
  InventoryGroupFull,
  InventoryHost,
  SnmpTestResponse,
  SnmpWithheldSummary,
  SshEnrichmentSummary,
} from '@/api/inventory';
import { credentialIdFromChoice, SETTINGS_SERVICE_CREDENTIAL } from '@/lib/credentialChoice';
import { type CustomDataFilterValue, isEmptyFilter, matchesCustomData } from '@/lib/customData';
import { isEmptyDeviceFilter, matchesDeviceFilter } from '@/lib/deviceModel';
import { descendantIdsOf, treeOrder } from '@/lib/tree';

const groupIdOf = (g: InventoryGroupFull) => g.id;
const groupParent = (g: InventoryGroupFull) => g.parent_id;

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
 * Groups and hosts that match a tag / custom field / device model filter. A
 * group that matches by its own tags or fields keeps all its hosts; a group
 * that matches only through some of its hosts keeps just those; a group with
 * neither is dropped, unless it is the ancestor of a kept group, which stays
 * (without hosts) so the tree still reads from the top. The device model
 * facets are host filters: with any set, only hosts that match them are kept,
 * and a group needs at least one such host. An empty filter returns `groups`
 * unchanged.
 */
export function filterGroupsByCustomData(
  groups: InventoryGroupFull[],
  filter: CustomDataFilterValue,
): InventoryGroupFull[] {
  if (isEmptyFilter(filter)) return groups;
  const byDevice = !isEmptyDeviceFilter(filter.device);
  const deviceMatch = (host: InventoryHost) => matchesDeviceFilter(host, filter.device);
  const kept = new Map<number, InventoryGroupFull>();
  for (const group of groups) {
    const all = group.hosts ?? [];
    if (matchesCustomData(group, filter)) {
      if (!byDevice) {
        kept.set(group.id, group);
        continue;
      }
      const hosts = all.filter(deviceMatch);
      if (hosts.length > 0) kept.set(group.id, { ...group, hosts });
      continue;
    }
    const hosts = all.filter((host) => matchesCustomData(host, filter) && deviceMatch(host));
    if (hosts.length > 0) kept.set(group.id, { ...group, hosts });
  }
  const parentOf = new Map(groups.map((g) => [g.id, g.parent_id ?? null]));
  const ancestors = new Set<number>();
  for (const id of kept.keys()) {
    for (let p = parentOf.get(id) ?? null; p != null && !ancestors.has(p); p = parentOf.get(p) ?? null) {
      ancestors.add(p);
    }
  }
  return groups.flatMap((g) => {
    const match = kept.get(g.id);
    if (match) return [match];
    return ancestors.has(g.id) ? [{ ...g, hosts: [] }] : [];
  });
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
  return treeOrder(groups, groupIdOf, groupParent, compare).map((e) => e.item);
}

/** The groups in tree order, siblings by the user's saved order (`orderedIds`). */
export function applyGroupOrder(groups: InventoryGroupFull[], orderedIds: number[]): InventoryGroupFull[] {
  const position = new Map(orderedIds.map((id, i) => [id, i]));
  const rank = (g: InventoryGroupFull) => position.get(g.id) ?? Number.MAX_SAFE_INTEGER;
  return treeSort(groups, (a, b) => rank(a) - rank(b));
}

/** The ids of a group's sub-groups at any depth (not the group itself). */
export function descendantIds(groups: InventoryGroupFull[], groupId: number): Set<number> {
  return descendantIdsOf(groups, groupIdOf, groupParent, groupId);
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

/**
 * One line on how discovery read show version over SSH, e.g. "SSH show
 * version (plexus-svc, service credential): read 11 of 13 hosts, 2 failed."
 * or why it was skipped. '' without a summary.
 */
export function describeSshEnrichment(summary: SshEnrichmentSummary | null | undefined): string {
  if (!summary) return '';
  const note = summary.note ? ` ${summary.note}.` : '';
  if (!summary.enabled) return 'SSH show version: off.';
  if (summary.skipped_reason) return `SSH show version skipped: ${summary.skipped_reason}.${note}`;
  const name = summary.credential || 'credential';
  const who =
    summary.credential_source === 'service'
      ? `${name}, service credential`
      : summary.credential_source === 'group'
        ? `${name}, remembered for this group`
        : name;
  const attempted = summary.attempted ?? 0;
  const enriched = summary.enriched ?? 0;
  const failed = summary.failed ?? 0;
  if (attempted === 0) return `SSH show version (${who}): no host answered on SSH.${note}`;
  return (
    `SSH show version (${who}): read ${enriched} of ${attempted} host${attempted === 1 ? '' : 's'}` +
    (failed ? `, ${failed} failed.` : '.') +
    note
  );
}

/**
 * One line on the scan targets probed without the group's SNMP settings
 * (the server's `snmp_withheld`), e.g. "SNMP: 3 addresses probed without
 * SNMP. <reason>". '' when every target got them.
 */
export function describeSnmpWithheld(summary: SnmpWithheldSummary | null | undefined): string {
  if (!summary || !summary.count) return '';
  const n = summary.count;
  return `SNMP: ${n} address${n === 1 ? '' : 'es'} probed without SNMP. ${summary.reason}`.trim();
}

/**
 * What a discovery scan or sync sends for the SSH credential select.
 * Untouched, with the group's remembered credential missing from the
 * user's list: nothing, so the server uses the group's credential if the
 * user may, else the service credential (and says why). Otherwise the
 * choice; the Settings service credential placeholder also tells the group
 * to forget its credential.
 */
export function discoveryCredentialOptions(
  choice: string,
  picked: boolean,
  groupCredentialId: number | null | undefined,
): { credentialId: number | null; useServiceCredential: boolean } {
  if (!picked && groupCredentialId != null && choice !== String(groupCredentialId))
    return { credentialId: null, useServiceCredential: false };
  return {
    credentialId: credentialIdFromChoice(choice),
    useServiceCredential: choice === SETTINGS_SERVICE_CREDENTIAL,
  };
}

/** "C9300-48P · 17.09.04a · S/N FOC2345X0AB" from what discovery learned. */
export function discoveredHostFacts(host: DiscoveredHost): string {
  const parts: string[] = [];
  if (host.model) parts.push(host.model);
  if (host.software_version) parts.push(host.software_version);
  if (host.serial_number) parts.push(`S/N ${host.serial_number}`);
  return parts.join(' · ');
}

/** The SSH error on one discovered host ('' when SSH read it or never tried). */
export function discoveredHostSshError(host: DiscoveredHost): string {
  const ssh = host.discovery?.ssh;
  return ssh && !ssh.ok ? ssh.error || 'SSH failed' : '';
}

/**
 * The `snmp_profile_id` a host save sends: on an edit only when the choice
 * differs from the saved one (so an edit that leaves it alone never touches
 * it), on a create only when a profile was chosen. undefined: send nothing.
 */
export function hostSnmpProfileToSend(
  saved: string | null | undefined,
  chosen: string,
  isEdit: boolean,
): string | undefined {
  if (isEdit) return chosen !== (saved ?? '') ? chosen : undefined;
  return chosen || undefined;
}

/**
 * The name of the host's own SNMP profile, for its row badge. null when the
 * host uses its group's profile, or its profile is not in the list (deleted).
 */
export function hostSnmpProfileName(
  host: Pick<InventoryHost, 'snmp_profile_id'>,
  profiles: { id: string; name: string }[],
): string | null {
  if (!host.snmp_profile_id) return null;
  return profiles.find((p) => p.id === host.snmp_profile_id)?.name ?? null;
}

/** What an SNMP profile test showed: the device it read, or why it failed. */
export type SnmpTestOutcome =
  | { ok: true; data: SnmpTestResponse['result'] }
  | { ok: false; error: string };

/** The outcome of an SNMP test response. */
export function snmpTestOutcome(response: SnmpTestResponse): SnmpTestOutcome {
  return response.success
    ? { ok: true, data: response.result }
    : { ok: false, error: response.error || 'Unknown error' };
}

/** " Stored N hardware components." after a serial fetch result; nothing at zero. */
export function componentsNote(count: number): string {
  if (count <= 0) return '';
  return ` Stored ${count} hardware component${count === 1 ? '' : 's'}.`;
}
