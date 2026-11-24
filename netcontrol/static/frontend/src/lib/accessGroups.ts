import type { AccessGroup } from '@/api/settings';

/** The ids of `value` that are not an access group any more (the group was
 *  deleted). Empty while the groups are not loaded: nothing is known then. */
export function missingGroupIds(value: number[], groups: AccessGroup[] | undefined): number[] {
  if (!groups) return [];
  const known = new Set(groups.map((g) => g.id));
  return value.filter((id) => !known.has(id));
}

/** One label per id, in the order given: the group's name, or a stand-in for
 *  a deleted group (or for any group while the list is not loaded). */
export function accessGroupLabels(ids: number[], groups: AccessGroup[] | undefined): string[] {
  const names = new Map((groups ?? []).map((g) => [g.id, g.name]));
  return ids.map((id) => names.get(id) ?? (groups ? `deleted group ${id}` : `group ${id}`));
}

/** `value` with `id` added (at the end) or removed. */
export function toggleGroupId(value: number[], id: number, on: boolean): number[] {
  const rest = value.filter((x) => x !== id);
  return on ? [...rest, id] : rest;
}

/** Whether a `{roles, groups}` rule allows admins and nobody else. */
export function isAdminsOnly(rule: { roles: string[]; groups: number[] }): boolean {
  return rule.groups.length === 0 && rule.roles.length > 0 && rule.roles.every((r) => r === 'admin');
}

/** A `{roles, groups}` rule in words, `open` for the empty rule (e.g. "users;
 *  access groups: NOC, Field"; "admins only" when no other role or group is
 *  named). */
export function accessRuleSummary(
  rule: { roles: string[]; groups: number[] } | undefined,
  groups: AccessGroup[] | undefined,
  open: string,
): string {
  if (!rule || (rule.roles.length === 0 && rule.groups.length === 0)) return open;
  if (isAdminsOnly(rule)) return 'admins only';
  const parts: string[] = [];
  // Admins are always allowed, so the admin role adds nothing next to another role or a group.
  const roles = rule.roles.filter((r) => r !== 'admin');
  if (roles.length > 0) parts.push(roles.map((r) => `${r}s`).join(', '));
  if (rule.groups.length > 0) parts.push(`access groups: ${accessGroupLabels(rule.groups, groups).join(', ')}`);
  return parts.join('; ');
}
