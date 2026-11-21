/**
 * Object-level permissions on the Configuration page: an account limited
 * to selected inventory groups may only read the devices of groups outside
 * ``write_group_ids``. The server enforces this (and returns only readable
 * rows); these helpers disable the write controls it would refuse.
 */
import { useAuthStatus } from '@/api/auth';
import { useInventoryGroups } from '@/api/compliance';
import { canWriteHost, hostGroupIds, READ_ONLY_GROUP_REASON } from '@/lib/objectScope';
import { canWriteFeature } from '@/lib/tabGating';

/** Why a raw backup download is off for this user. */
export const RAW_BACKUP_REASON =
  'Downloading a backup needs config-backups write access: it holds device secrets. View shows it with secrets masked.';

/** Whether this user may download raw config backups (device secrets
 * included): an admin or a holder of `config-backups.write`, as the
 * server requires. Others get the masked view only. */
export function useCanDownloadBackups(): boolean {
  return canWriteFeature('config-backups', useAuthStatus().data);
}

/** ``(hostId) => may change it`` for rows that carry a host id but not its
 * group (backups, drift events). Restricted accounts look the group up in
 * the inventory list (with hosts); unrestricted ones fetch nothing. */
export function useCanWriteHost(): (hostId: number | null | undefined) => boolean {
  const { data } = useAuthStatus();
  const scope = data?.object_scope;
  const groups = useInventoryGroups(true, Boolean(scope?.restricted));
  const hostGroups = hostGroupIds(groups.data);
  return (hostId) => canWriteHost(scope, hostGroups, hostId);
}

/** The ``disabled``/``title`` props of a write control. */
export function writeControl(canWrite: boolean, disabled = false): { disabled: boolean; title?: string } {
  return canWrite ? { disabled } : { disabled: true, title: READ_ONLY_GROUP_REASON };
}
