import { useState } from 'react';

import {
  type ValidationObjectType,
  type ValidationRule,
  type ViolationReport,
  useCheckExistingData,
  useDeleteValidationRule,
  useRuleFields,
  useUpdateValidationRule,
  useValidationRules,
} from '@/api/validationRules';
import { Badge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { DataTable } from '@/components/DataTable';
import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { ValidationRuleModal } from './ValidationRuleModal';
import { OBJECT_TYPE_LABEL, describeRule, fieldLabel } from './validationRules';

const RIGHT = { textAlign: 'right' } as const;

/** The "Check existing data" report: objects saved before a rule existed, or by discovery. */
function ViolationsReport({ report }: { report: ViolationReport }) {
  if (report.objects.length === 0) {
    return (
      <Callout tone="success">
        {report.checked === 0
          ? 'No enabled rules to check.'
          : `All ${report.checked.toLocaleString()} checked objects pass the enabled rules.`}
      </Callout>
    );
  }
  return (
    <div className="stack stack-sm">
      <div className="form-help" style={{ margin: 0 }}>
        {report.objects.length.toLocaleString()} of {report.checked.toLocaleString()} checked objects break an
        enabled rule{report.truncated ? ' (only the first ones are listed)' : ''}. They save again only once fixed.
      </div>
      <DataTable compact aria-label="Objects that break validation rules">
        <thead>
          <tr>
            <th>Object</th>
            <th>Type</th>
            <th>Problems</th>
          </tr>
        </thead>
        <tbody>
          {report.objects.map((o) => (
            <tr key={`${o.object_type}:${o.object_key}`}>
              <td style={{ overflowWrap: 'anywhere' }}>{o.label || o.object_key}</td>
              <td>{OBJECT_TYPE_LABEL[o.object_type] ?? o.object_type}</td>
              <td>
                <ul style={{ margin: 0, paddingLeft: 'var(--space-4)' }}>
                  {o.violations.map((v) => (
                    <li key={`${v.rule}:${v.field}`}>
                      <code>{v.field}</code>: {v.message} <span className="text-muted">({v.rule})</span>
                    </li>
                  ))}
                </ul>
              </td>
            </tr>
          ))}
        </tbody>
      </DataTable>
    </div>
  );
}

/** Settings tab: admin-defined checks the server runs on inventory and IPAM writes. */
export function ValidationRulesTab() {
  const rulesQ = useValidationRules();
  const fieldsQ = useRuleFields();
  const update = useUpdateValidationRule();
  const remove = useDeleteValidationRule();
  const check = useCheckExistingData();
  const toggling = usePendingKeys<number>();
  const deleting = usePendingKeys<number>();
  const { confirm, alert } = useDialogs();
  const [editing, setEditing] = useState<ValidationRule | 'new' | null>(null);
  const [checkType, setCheckType] = useState<ValidationObjectType | ''>('');

  const rules = rulesQ.data?.rules ?? [];
  const catalogue = fieldsQ.data;
  const addButton = (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')} disabled={!catalogue}>
      Add rule
    </button>
  );

  const toggle = (rule: ValidationRule) =>
    void toggling.run(rule.id, async () => {
      try {
        await update.mutateAsync({ id: rule.id, data: { enabled: !rule.enabled } });
      } catch (err) {
        await alert({
          title: 'Rule not changed',
          message: `"${rule.name}" was not ${rule.enabled ? 'disabled' : 'enabled'}: ${(err as Error).message} Try again.`,
          variant: 'error',
        });
      }
    });

  const handleDelete = (rule: ValidationRule) =>
    void deleting.run(rule.id, async () => {
      const agreed = await confirm({
        title: 'Delete validation rule',
        message: `Delete the rule "${rule.name}"? Saves are no longer checked against it.`,
        confirmLabel: 'Delete rule',
      });
      if (!agreed) return;
      try {
        await remove.mutateAsync(rule.id);
      } catch (err) {
        await alert({
          title: 'Rule not deleted',
          message: `The rule "${rule.name}" was not deleted: ${(err as Error).message} Try again.`,
          variant: 'error',
        });
      }
    });

  if (rulesQ.isError && !rulesQ.data) return <QueryError what="validation rules" query={rulesQ} />;
  if (fieldsQ.isError && !fieldsQ.data) return <QueryError what="validation rule fields" query={fieldsQ} />;
  if (rulesQ.isPending || fieldsQ.isPending) return <LoadingState />;

  return (
    <div className="stack">
      <div className="stack stack-sm">
        {rules.length > 0 && <div style={{ display: 'flex', justifyContent: 'flex-end' }}>{addButton}</div>}
        {rules.length === 0 ? (
          <EmptyState
            compact
            message="No validation rules yet."
            description="Add a rule to require, for example, that hostnames match a naming pattern. Hosts, groups, IPAM prefixes and addresses, VLANs and VRFs are checked when they are saved."
            action={addButton}
          />
        ) : (
          <DataTable compact aria-label="Validation rules">
            <thead>
              <tr>
                <th>Name</th>
                <th>Applies to</th>
                <th>Rule</th>
                <th style={RIGHT}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.id}>
                  <td>
                    {rule.name}
                    {!rule.enabled && (
                      <>
                        {' '}
                        <Badge tone="neutral" size="sm">
                          Disabled
                        </Badge>
                      </>
                    )}
                    {rule.description && (
                      <div className="form-help" style={{ margin: 0 }}>
                        {rule.description}
                      </div>
                    )}
                  </td>
                  <td>
                    {OBJECT_TYPE_LABEL[rule.object_type] ?? rule.object_type}
                    <div className="form-help" style={{ margin: 0 }}>
                      {fieldLabel(rule.field, catalogue?.fields[rule.object_type])}
                    </div>
                  </td>
                  <td style={{ overflowWrap: 'anywhere' }}>
                    {describeRule(rule)}
                    {rule.error_message && (
                      <div className="form-help" style={{ margin: 0 }}>
                        &ldquo;{rule.error_message}&rdquo;
                      </div>
                    )}
                  </td>
                  <td style={RIGHT}>
                    <div
                      style={{ display: 'inline-flex', gap: 'var(--space-1)', flexWrap: 'wrap', justifyContent: 'flex-end' }}
                    >
                      <BusyButton
                        className="btn btn-sm btn-secondary"
                        busy={toggling.isPending(rule.id)}
                        onClick={() => toggle(rule)}
                      >
                        {rule.enabled ? 'Disable' : 'Enable'}
                      </BusyButton>
                      <button type="button" className="btn btn-sm btn-secondary" onClick={() => setEditing(rule)}>
                        Edit
                      </button>
                      <DeleteButton
                        busy={deleting.isPending(rule.id)}
                        onClick={() => handleDelete(rule)}
                        aria-label={`Delete validation rule ${rule.name}`}
                      />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </DataTable>
        )}
      </div>

      <section className="stack stack-sm">
        <h4 style={{ margin: 0 }}>Check existing data</h4>
        <div className="form-help" style={{ margin: 0 }}>
          Rules are checked when an object is saved in Plexus, not on objects saved earlier or added by discovery,
          collectors and IPAM syncs. List the stored objects that break an enabled rule.
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap' }}>
          <select
            aria-label="Object type to check"
            className="form-select"
            style={{ maxWidth: '14rem' }}
            value={checkType}
            onChange={(e) => setCheckType(e.target.value as ValidationObjectType | '')}
          >
            <option value="">All object types</option>
            {(catalogue?.object_types ?? []).map((t) => (
              <option key={t} value={t}>
                {OBJECT_TYPE_LABEL[t] ?? t}
              </option>
            ))}
          </select>
          <BusyButton
            className="btn btn-sm btn-primary"
            busy={check.isPending}
            busyLabel="Checking…"
            onClick={() => check.mutate(checkType || null)}
          >
            Check existing data
          </BusyButton>
        </div>
        {check.isError && (
          <Callout tone="danger">The check did not run: {check.error.message} Try again.</Callout>
        )}
        {check.data && <ViolationsReport report={check.data} />}
      </section>

      {editing && catalogue && (
        <ValidationRuleModal
          rule={editing === 'new' ? null : editing}
          catalogue={catalogue}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  );
}
