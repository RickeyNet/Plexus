/**
 * Object-level permissions in the SPA: an account limited to selected
 * inventory groups (``object_scope.restricted`` on the auth status) may
 * change only the groups in ``write_group_ids`` (ids already expanded with
 * their sub-groups). The server enforces this; the helpers here only
 * disable the controls it would refuse and say why.
 */
import { useAuthStatus, type ObjectScopeStatus } from '@/api/auth';

/** Why a write control is disabled for a group the account may only read. */
export const READ_ONLY_GROUP_REASON = 'Read-only access to this inventory group';
/** Why a scoped account cannot create a group at the top level. */
export const TOP_LEVEL_GROUP_REASON =
  'Only accounts with access to all devices can create a top-level group';

/** Whether the account may change ``groupId``. A missing scope (an older
 * server, or the status not loaded yet) is unrestricted: the server still
 * refuses what it must. */
export function canWriteGroup(
  scope: ObjectScopeStatus | undefined,
  groupId: number | null | undefined,
): boolean {
  if (!scope?.restricted) return true;
  return groupId != null && scope.write_group_ids.includes(groupId);
}

/** The ``groups`` the account may change (all of them when unrestricted):
 * the choices of a "target group" dropdown. */
export function writableGroups<T extends { id: number }>(
  scope: ObjectScopeStatus | undefined,
  groups: T[],
): T[] {
  if (!scope?.restricted) return groups;
  return groups.filter((g) => canWriteGroup(scope, g.id));
}

/** ``host id -> inventory group id`` from groups listed with their hosts
 * (``GET /api/inventory?include_hosts=true``). */
export function hostGroupIds(
  groups: { id: number; hosts?: { id: number }[] }[] | undefined,
): Map<number, number> | undefined {
  if (!groups) return undefined;
  const out = new Map<number, number>();
  for (const group of groups) {
    for (const host of group.hosts ?? []) out.set(host.id, group.id);
  }
  return out;
}

/** Whether the account may change the device ``hostId``, given its group
 * from ``hostGroups``. Before the map is loaded the control stays enabled:
 * the server refuses what it must. */
export function canWriteHost(
  scope: ObjectScopeStatus | undefined,
  hostGroups: Map<number, number> | undefined,
  hostId: number | null | undefined,
): boolean {
  if (!scope?.restricted) return true;
  if (hostId == null) return false;
  if (!hostGroups) return true;
  return canWriteGroup(scope, hostGroups.get(hostId));
}

export interface ObjectScopeAccess {
  /** The account is limited to selected inventory groups. */
  restricted: boolean;
  /** Restricted with no writable grant or scope rule: every write control
   * is hidden or disabled (``canWriteFeature`` already answers false). */
  readOnly: boolean;
  canWriteGroup: (groupId: number | null | undefined) => boolean;
  /** The given groups the account may change. */
  writableGroups: <T extends { id: number }>(groups: T[]) => T[];
}

/** The signed-in account's object scope. */
export function useObjectScope(): ObjectScopeAccess {
  const { data } = useAuthStatus();
  const scope = data?.object_scope;
  return {
    restricted: Boolean(scope?.restricted),
    readOnly: Boolean(scope?.restricted && scope.read_only),
    canWriteGroup: (groupId) => canWriteGroup(scope, groupId),
    writableGroups: (groups) => writableGroups(scope, groups),
  };
}

/** Whether the signed-in account may change ``groupId``. */
export function useCanWriteGroup(groupId: number | null | undefined): boolean {
  return useObjectScope().canWriteGroup(groupId);
}
