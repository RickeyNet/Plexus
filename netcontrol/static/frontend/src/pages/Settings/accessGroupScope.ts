/**
 * Device access of an access group (object-level permissions): either every
 * device, or only the granted inventory groups, each read only or read and
 * write. A grant covers the group's sub-groups too.
 */
import type { AccessGroup, InventoryScopeGrant, ObjectScope, ScopeRule } from '@/api/settings';

/** The access one inventory group gets in the dialog. */
export type GrantChoice = 'none' | 'read' | 'write';

/** What an account limited to selected inventory groups sees: every page
 * it has the feature for, filtered to its objects. */
export const SCOPED_ACCOUNT_NOTE =
  'Accounts limited this way keep every page their features allow, filtered: devices and their records ' +
  '(monitoring, jobs, compliance, software, MAC tracking, topology ...) in the granted groups, and IPAM, ' +
  'DCIM, circuits and virtualization records of the tenants of those devices and the sites they stand in. ' +
  'Shared catalogues are read only. Scope rules below add tenants or sites per record type. AI access ' +
  'stays closed to them.';

/** A key for one scope rule (model, attribute, value). */
export function ruleKey(rule: Pick<ScopeRule, 'model' | 'attribute' | 'value_id'>): string {
  return `${rule.model}|${rule.attribute}|${rule.value_id}`;
}

/** The rules to send: complete ones only (a value picked), one per key
 * (write wins), sorted. */
export function normaliseRules(rules: Partial<ScopeRule>[]): ScopeRule[] {
  const out = new Map<string, ScopeRule>();
  for (const r of rules) {
    if (!r.model || !r.attribute || !r.value_id) continue;
    const rule: ScopeRule = { model: r.model, attribute: r.attribute, value_id: r.value_id, can_write: Boolean(r.can_write) };
    const prev = out.get(ruleKey(rule));
    out.set(ruleKey(rule), prev ? { ...rule, can_write: prev.can_write || rule.can_write } : rule);
  }
  return Array.from(out.values()).sort((a, b) => ruleKey(a).localeCompare(ruleKey(b)));
}

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
