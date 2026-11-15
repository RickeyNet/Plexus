/**
 * Device access of an access group (object-level permissions): either every
 * device, or only the granted inventory groups, each read only or read and
 * write. A grant covers the group's sub-groups too.
 */
import type { AccessGroup, InventoryScopeGrant, ObjectScope } from '@/api/settings';

/** The access one inventory group gets in the dialog. */
export type GrantChoice = 'none' | 'read' | 'write';

/** The pages an account limited to selected inventory groups can use. Every
 * other page is closed to it until its module enforces the limit. */
export const SCOPED_ACCOUNT_PAGES = [
  'Inventory',
  'Configuration (Config Drift, Intended, Backups, Config Search)',
  'Credentials (their own)',
];

/** The dialog's per-group choices from an access group's grants. */
export function choicesFromGrants(grants: InventoryScopeGrant[] | undefined): Map<number, GrantChoice> {
  const choices = new Map<number, GrantChoice>();
  for (const grant of grants ?? []) {
    choices.set(grant.inventory_group_id, grant.can_write ? 'write' : 'read');
  }
  return choices;
}

/** The grants to send for the dialog's choices (sorted by group id). */
export function grantsFromChoices(choices: Map<number, GrantChoice>): InventoryScopeGrant[] {
  return Array.from(choices.entries())
    .filter(([, choice]) => choice !== 'none')
    .sort(([a], [b]) => a - b)
    .map(([inventory_group_id, choice]) => ({ inventory_group_id, can_write: choice === 'write' }));
}

/** The object scope part of an access group save: grants only with ``groups``. */
export function scopePayload(
  scope: ObjectScope,
  choices: Map<number, GrantChoice>,
): { object_scope: ObjectScope; inventory_scopes: InventoryScopeGrant[] } {
  return { object_scope: scope, inventory_scopes: scope === 'groups' ? grantsFromChoices(choices) : [] };
}

/** One line for the access group table: what devices its members see. */
export function scopeSummary(
  group: Pick<AccessGroup, 'object_scope' | 'inventory_scopes'>,
  groupNames: Map<number, string>,
): string {
  if (group.object_scope !== 'groups') return 'All devices';
  const grants = group.inventory_scopes ?? [];
  if (grants.length === 0) return 'No devices (no inventory groups granted)';
  const label = (g: InventoryScopeGrant) =>
    `${groupNames.get(g.inventory_group_id) ?? `Group ${g.inventory_group_id}`} (${g.can_write ? 'read and write' : 'read'})`;
  return `Selected inventory groups: ${grants.map(label).join(', ')}`;
}
