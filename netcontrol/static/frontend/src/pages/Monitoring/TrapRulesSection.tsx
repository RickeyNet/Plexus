import { useId, useState, type FormEvent } from 'react';

import { SeverityBadge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { DataTable } from '@/components/DataTable';
import { DeleteButton } from '@/components/DeleteButton';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import {
  useCreateTrapRule,
  useDeleteTrapRule,
  usePatchBuiltinTrapRule,
  useTestTrap,
  useTrapRules,
  useUpdateTrapRule,
  type SyslogRule,
  type SyslogSeverity,
  type TrapCondition,
  type TrapConditionOp,
} from '@/api/syslogRules';

import { INACTIVE_OPACITY } from './helpers';
import { RuleNameField, RuleSeverityField, RuleThresholdFields } from './RuleSettingsFields';
import {
  autoResolveLabel,
  conditionLabel,
  EMPTY_TRAP_CONDITION,
  EMPTY_TRAP_RULE_FORM,
  parseVarbindLines,
  SYSLOG_SEVERITY_OPTIONS,
  thresholdLabel,
  TRAP_CONDITION_OPS,
  trapBodyFromForm,
  trapFormFromRule,
  trapInstanceLabel,
  type TrapRuleForm,
} from './syslogRules';
import { useRuleRowActions } from './useRuleRowActions';

// Monitoring -> Configure -> Syslog Rules: the SNMP trap rules, listed under
// the syslog rules. The built-in ones (enable and severity only) and the
// operator's custom ones (a trap OID, prefix or name, varbind conditions, an
// instance and an optional clearing trap). Their alerts are their own family,
// metric trap_<key> (docs/snmp-traps.md).
export function TrapRulesSection() {
  const rules = useTrapRules();
  const { change, remove, pending, deleting } = useRuleRowActions({
    patchBuiltin: usePatchBuiltinTrapRule(),
    updateCustom: useUpdateTrapRule(),
    deleteCustom: useDeleteTrapRule(),
    what: 'trap rule',
  });
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<SyslogRule | null>(null);

  return (
    <section style={{ marginTop: '1.5rem' }}>
      <div className="toolbar" style={{ justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
        <h3 style={{ margin: 0 }}>SNMP trap rules</h3>
        <button className="btn btn-primary" onClick={() => setCreating(true)}>+ New Trap Rule</button>
      </div>
      <p className="text-muted" style={{ fontSize: '0.85em', marginTop: '0.25rem' }}>
        Rules run on the server against traps from inventory hosts that carry the host&apos;s SNMP community (or its
        SNMPv3 user). Their alerts have metric <code>trap_&lt;rule&gt;</code>, apart from the syslog and polled alerts. A
        Cisco <code>clogMessageGenerated</code> trap also goes through the syslog rules above.
      </p>
      {rules.error && !rules.data ? <QueryError what="trap rules" query={rules} /> : rules.isPending && <LoadingState />}
      {rules.data && (rules.data.length === 0 ? (
        <EmptyState message="No trap rules" />
      ) : (
        <DataTable aria-label="SNMP trap rules">
          <thead>
            <tr>
              <th>Rule</th>
              <th>Traps</th>
              <th>Severity</th>
              <th>Threshold</th>
              <th>Auto-resolve</th>
              <th aria-label="Actions" />
            </tr>
          </thead>
          <tbody>
            {rules.data.map((r) => {
              const busy = pending.isPending(r.key);
              return (
                <tr key={r.key}>
                  <td style={{ opacity: r.enabled ? 1 : INACTIVE_OPACITY }}>
                    <strong>{r.name}</strong>
                    {r.builtin && <span className="text-muted" style={{ fontSize: '0.75em', marginLeft: '0.4rem' }}>built-in</span>}
                    {!r.enabled && <span className="text-muted" style={{ fontSize: '0.75em', marginLeft: '0.3rem' }}>(disabled)</span>}
                    {r.description && <div className="text-muted" style={{ fontSize: '0.8em' }}>{r.description}</div>}
                    {r.families.length > 0 && (
                      <div className="text-muted" style={{ fontSize: '0.8em' }}>{r.families.join(', ')}</div>
                    )}
                  </td>
                  <td style={{ fontSize: '0.82em', maxWidth: '28rem', overflowWrap: 'anywhere' }}>
                    {r.builtin ? (
                      <>
                        <code>{r.tags.join(', ')}</code>
                        {r.clear_tags.length > 0 && <div className="text-muted">Clears: <code>{r.clear_tags.join(', ')}</code></div>}
                      </>
                    ) : (
                      <>
                        <code>{r.pattern}</code>
                        {r.trap_match?.conditions.map((c, i) => (
                          <div key={i} className="text-muted">where <code>{conditionLabel(c)}</code></div>
                        ))}
                        <div className="text-muted">{trapInstanceLabel(r.trap_match)}</div>
                        {r.clear_pattern && <div className="text-muted">Clears: <code>{r.clear_pattern}</code></div>}
                      </>
                    )}
                  </td>
                  <td>
                    <label className="sr-only" htmlFor={`trap-sev-${r.key}`}>Severity of {r.name}</label>
                    <select
                      id={`trap-sev-${r.key}`}
                      className="form-select"
                      style={{ width: 'auto', minWidth: '7rem' }}
                      value={r.severity}
                      disabled={busy}
                      onChange={(e) => void change(r, { severity: e.target.value as SyslogSeverity })}
                    >
                      {SYSLOG_SEVERITY_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                    </select>
                  </td>
                  <td style={{ whiteSpace: 'nowrap' }}>{thresholdLabel(r)}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>{autoResolveLabel(r.auto_resolve_minutes)}</td>
                  <td>
                    <div style={{ display: 'flex', gap: '0.4rem', justifyContent: 'flex-end' }}>
                      {!r.builtin && <button className="btn btn-sm btn-secondary" onClick={() => setEditing(r)}>Edit</button>}
                      <BusyButton className="btn btn-sm btn-secondary" busy={busy} onClick={() => void change(r, { enabled: !r.enabled })}>
                        {r.enabled ? 'Disable' : 'Enable'}
                      </BusyButton>
                      {!r.builtin && <DeleteButton busy={deleting.isPending(r.key)} onClick={() => void remove(r)} />}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </DataTable>
      ))}

      <TrapRuleModal rule={editing} isCreate={creating} onClose={() => { setEditing(null); setCreating(false); }} />
    </section>
  );
}

// The varbind conditions of one side of a rule: each a varbind (registry
// object name or OID), an operator and a value; all must hold.
function TrapConditionsField({ formId, label, conditions, onChange }: {
  formId: string;
  label: string;
  conditions: TrapCondition[];
  onChange: (conditions: TrapCondition[]) => void;
}) {
  function update(index: number, changes: Partial<TrapCondition>) {
    onChange(conditions.map((c, i) => (i === index ? { ...c, ...changes } : c)));
  }

  return (
    <fieldset className="form-group" style={{ border: 0, padding: 0, margin: '0 0 0.75rem 0' }}>
      <legend className="form-label">{label}</legend>
      {conditions.map((c, i) => (
        <div key={i} style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', marginBottom: '0.4rem' }}>
          <label className="sr-only" htmlFor={`${formId}-obj-${i}`}>Varbind {i + 1}</label>
          <input id={`${formId}-obj-${i}`} className="form-input" style={{ flex: '2 1 10rem' }} placeholder="ifAdminStatus or OID" value={c.object} onChange={(e) => update(i, { object: e.target.value })} maxLength={300} />
          <label className="sr-only" htmlFor={`${formId}-op-${i}`}>Operator {i + 1}</label>
          <select id={`${formId}-op-${i}`} className="form-select" style={{ flex: '0 1 9rem' }} value={c.op} onChange={(e) => update(i, { op: e.target.value as TrapConditionOp })}>
            {TRAP_CONDITION_OPS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
          <label className="sr-only" htmlFor={`${formId}-val-${i}`}>Value {i + 1}</label>
          <input id={`${formId}-val-${i}`} className="form-input" style={{ flex: '2 1 8rem' }} placeholder="up" value={c.value} onChange={(e) => update(i, { value: e.target.value })} maxLength={200} />
          <button type="button" className="btn btn-sm btn-secondary" aria-label={`Remove condition ${i + 1}`} onClick={() => onChange(conditions.filter((_c, j) => j !== i))}>
            Remove
          </button>
        </div>
      ))}
      {conditions.length < 10 && (
        <button type="button" className="btn btn-sm btn-secondary" onClick={() => onChange([...conditions, EMPTY_TRAP_CONDITION])}>
          + Add Condition
        </button>
      )}
    </fieldset>
  );
}

// Create (rule == null, isCreate) or edit (rule set) a custom trap rule, with
// a box to try the draft against a trap OID and its varbinds.
function TrapRuleModal({ rule, isCreate, onClose }: { rule: SyslogRule | null; isCreate: boolean; onClose: () => void }) {
  const formId = useId();
  const isOpen = isCreate || rule != null;
  const createMut = useCreateTrapRule();
  const updateMut = useUpdateTrapRule();
  const testMut = useTestTrap();
  const [form, setForm] = useState<TrapRuleForm>(EMPTY_TRAP_RULE_FORM);
  const [saveError, setSaveError] = useState('');
  const [sampleOid, setSampleOid] = useState('');
  const [sampleVarbinds, setSampleVarbinds] = useState('');

  // Load the form when the modal opens for another rule (or for a new one).
  const [prevRule, setPrevRule] = useState(rule);
  const [prevIsCreate, setPrevIsCreate] = useState(isCreate);
  if (rule !== prevRule || isCreate !== prevIsCreate) {
    setPrevRule(rule);
    setPrevIsCreate(isCreate);
    setSaveError('');
    testMut.reset();
    setForm(rule ? trapFormFromRule(rule) : EMPTY_TRAP_RULE_FORM);
  }

  function patch(changes: Partial<TrapRuleForm>) {
    setForm((prev) => ({ ...prev, ...changes }));
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSaveError('');
    const body = trapBodyFromForm(form);
    const onError = (err: Error) => setSaveError(err.message);
    if (rule?.id != null) updateMut.mutate({ id: rule.id, data: body }, { onSuccess: onClose, onError });
    else createMut.mutate(body, { onSuccess: onClose, onError });
  }

  function runTest() {
    const draft = trapBodyFromForm(form);
    testMut.mutate({
      trap_oid: sampleOid.trim(),
      varbinds: parseVarbindLines(sampleVarbinds),
      rule: draft.name && draft.pattern ? draft : undefined,
    });
  }

  const saving = createMut.isPending || updateMut.isPending;
  const result = testMut.data;

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={rule ? 'Edit Trap Rule' : 'Create Trap Rule'}
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={saving}>
            {saving ? 'Saving…' : rule ? 'Save Rule' : 'Create Rule'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        <RuleNameField formId={formId} value={form.name} onChange={patch} />
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-traps`}>Raising traps</label>
          <input id={`${formId}-traps`} className="form-input" value={form.pattern} onChange={(e) => patch({ pattern: e.target.value })} required maxLength={500} aria-describedby={`${formId}-traps-hint`} placeholder="cefcModuleStatusChange or 1.3.6.1.4.1.32473.2.0.5" />
          <div id={`${formId}-traps-hint`} className="text-muted" style={{ fontSize: '0.78em', marginTop: '0.2rem' }}>
            Comma separated trap OIDs, OID prefixes ending in <code>.*</code>, or trap names the registry knows.
          </div>
        </div>
        <TrapConditionsField formId={`${formId}-raise`} label="Only when (optional)" conditions={form.conditions} onChange={(conditions) => patch({ conditions })} />
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <div className="form-group" style={{ flex: '2 1 12rem' }}>
            <label className="form-label" htmlFor={`${formId}-inst`}>Instance varbind (blank = one alert per device)</label>
            <input id={`${formId}-inst`} className="form-input" value={form.instance_object} onChange={(e) => patch({ instance_object: e.target.value })} maxLength={300} placeholder="ifIndex or OID" />
          </div>
          <div className="form-group" style={{ flex: '1 1 8rem' }}>
            <label className="form-label" htmlFor={`${formId}-part`}>Instance from</label>
            <select id={`${formId}-part`} className="form-select" value={form.instance_part} onChange={(e) => patch({ instance_part: e.target.value as 'value' | 'index' })}>
              <option value="value">Its value</option>
              <option value="index">Its index</option>
            </select>
          </div>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-clear`}>Clearing traps (optional)</label>
          <input id={`${formId}-clear`} className="form-input" value={form.clear_pattern} onChange={(e) => patch({ clear_pattern: e.target.value })} maxLength={500} />
        </div>
        {form.clear_pattern.trim() && (
          <TrapConditionsField formId={`${formId}-clear`} label="Clear only when (optional)" conditions={form.clear_conditions} onChange={(clear_conditions) => patch({ clear_conditions })} />
        )}
        <RuleSeverityField formId={formId} value={form.severity} onChange={patch} />
        <RuleThresholdFields formId={formId} form={form} onChange={patch} />

        <div className="form-group" style={{ marginTop: '1rem' }}>
          <label className="form-label" htmlFor={`${formId}-oid`}>Test against a trap: its OID</label>
          <input id={`${formId}-oid`} className="form-input" value={sampleOid} onChange={(e) => setSampleOid(e.target.value)} placeholder="1.3.6.1.6.3.1.1.5.3" maxLength={300} />
          <label className="form-label" htmlFor={`${formId}-vbs`} style={{ marginTop: '0.4rem' }}>Its varbinds, one per line (OID = value)</label>
          <textarea id={`${formId}-vbs`} className="form-input" rows={3} value={sampleVarbinds} onChange={(e) => setSampleVarbinds(e.target.value)} placeholder="1.3.6.1.2.1.2.2.1.1.12 = 12" />
          <div style={{ marginTop: '0.4rem' }}>
            <BusyButton type="button" className="btn btn-sm btn-secondary" busy={testMut.isPending} disabled={!sampleOid.trim()} onClick={runTest}>
              Test Trap
            </BusyButton>
          </div>
        </div>
        {testMut.error && <Callout tone="danger">{testMut.error.message}</Callout>}
        {result && (
          <div className="card card-sm" style={{ fontSize: '0.85em' }} aria-live="polite">
            <div><span className="text-muted">Trap:</span> <code>{result.name || result.trap_oid}</code></div>
            {result.varbinds.length > 0 && (
              <div>
                <span className="text-muted">Varbinds:</span>{' '}
                {result.varbinds.map((v) => `${v.name ? `${v.name}${v.index ? `.${v.index}` : ''}` : v.oid} = ${v.label}`).join(', ')}
              </div>
            )}
            {result.draft && (
              <div>
                <span className="text-muted">This rule:</span>{' '}
                {result.draft.action
                  ? `${result.draft.action === 'raise' ? 'matches (raises)' : 'clears'}${result.draft.instance ? ` · instance ${result.draft.instance}` : ''}`
                  : 'no match'}
              </div>
            )}
            <div>
              <span className="text-muted">Other rules:</span>{' '}
              {result.matches.length === 0
                ? 'none'
                : result.matches.map((m) => (
                  <span key={m.key} style={{ marginRight: '0.6rem' }}>
                    <SeverityBadge severity={m.action === 'raise' ? 'warning' : 'info'}>{m.action}</SeverityBadge> {m.name}
                    {m.instance && ` (${m.instance})`}
                    {!m.enabled && ' (disabled)'}
                  </span>
                ))}
            </div>
            {result.config_change && <div>Starts a config backup and drift check of the host.</div>}
            {result.repoll && <div>Re-polls the host.</div>}
            {result.syslog_line && (
              <div>
                <span className="text-muted">Syslog line:</span> <code>{result.syslog_line}</code>
                {result.syslog && result.syslog.matches.length > 0 && ` (syslog rules: ${result.syslog.matches.map((m) => `${m.action} ${m.name}`).join(', ')})`}
              </div>
            )}
          </div>
        )}
      </form>
    </Modal>
  );
}
