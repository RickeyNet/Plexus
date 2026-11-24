import type { SyslogRule, SyslogSeverity } from '@/api/syslogRules';
import { useDialogs } from '@/components/DialogProvider-context';
import { usePendingKeys } from '@/lib/usePendingKeys';

type Change = { enabled?: boolean; severity?: SyslogSeverity };

/**
 * The row actions of a rule list (syslog or SNMP trap rules): enable /
 * disable or change the severity of a built-in rule (its patch) or a custom
 * one (its update), and delete a custom rule after a confirmation. Errors
 * show in an alert; each row is busy on its own (`usePendingKeys`).
 */
export function useRuleRowActions({
  patchBuiltin,
  updateCustom,
  deleteCustom,
  what,
}: {
  patchBuiltin: { mutateAsync: (vars: { key: string; data: Change }) => Promise<unknown> };
  updateCustom: { mutateAsync: (vars: { id: number; data: Change }) => Promise<unknown> };
  deleteCustom: { mutateAsync: (id: number) => Promise<unknown> };
  /** "syslog rule", "trap rule": the confirmation's wording. */
  what: string;
}) {
  const { confirm, alert } = useDialogs();
  const pending = usePendingKeys<string>();
  const deleting = usePendingKeys<string>();

  function change(rule: SyslogRule, data: Change) {
    return pending.run(rule.key, async () => {
      try {
        if (rule.builtin) await patchBuiltin.mutateAsync({ key: rule.key, data });
        else if (rule.id != null) await updateCustom.mutateAsync({ id: rule.id, data });
      } catch (e) {
        void alert({ message: (e as Error).message, variant: 'error' });
      }
    });
  }

  async function remove(rule: SyslogRule) {
    if (rule.id == null) return;
    const id = rule.id;
    const ok = await confirm({
      title: `Delete ${what}`,
      message: `Delete rule '${rule.name}'? Its open alerts are resolved.`,
      confirmLabel: 'Delete',
    });
    if (!ok) return;
    await deleting.run(rule.key, async () => {
      try {
        await deleteCustom.mutateAsync(id);
      } catch (e) {
        void alert({ message: (e as Error).message, variant: 'error' });
      }
    });
  }

  return { change, remove, pending, deleting };
}
