import { useId, useState, type FormEvent } from 'react';

import { SeverityBadge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { DataTable } from '@/components/DataTable';
import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import {
  useCreateSyslogRule,
  useDeleteSyslogRule,
  usePatchBuiltinSyslogRule,
  useSyslogActivity,
  useSyslogRules,
  useTestSyslogMessage,
  useUpdateSyslogRule,
  type SyslogMatchType,
  type SyslogRule,
  type SyslogSeverity,
} from '@/api/syslogRules';
import { formatBackendDateTime } from '@/lib/datetime';
import { formatCount } from '@/lib/formatCount';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { INACTIVE_OPACITY } from './helpers';
import { SyslogActivitySection } from './SyslogActivitySection';
import {
  activityByKey,
  activityWindowLabel,
  autoResolveLabel,
  bodyFromForm,
  countLabel,
  DEFAULT_SYSLOG_ACTIVITY_HOURS,
  EMPTY_SYSLOG_RULE_FORM,
  formFromRule,
  recollectLabel,
  repollLabel,
  ruleMatchCounts,
  SYSLOG_MATCH_TYPES,
  SYSLOG_SEVERITY_OPTIONS,
  thresholdLabel,
  type SyslogRuleForm,
  type SyslogRulePrefill,
} from './syslogRules';

// Monitoring -> Configure -> Syslog Rules: the built-in rules (enable and
// severity only) and the custom rules that turn received syslog messages
// into alerts (docs/syslog-rules.md).
export function SyslogRulesTab() {
  const { confirm, alert } = useDialogs();
  const rules = useSyslogRules();
  const patchBuiltin = usePatchBuiltinSyslogRule();
  const updateCustom = useUpdateSyslogRule();
  const deleteMut = useDeleteSyslogRule();
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<SyslogRule | null>(null);
  const pending = usePendingKeys<string>();
  const deleting = usePendingKeys<string>();
  const [hours, setHours] = useState(DEFAULT_SYSLOG_ACTIVITY_HOURS);
  const activity = useSyslogActivity(hours);
  const matchesByKey = activityByKey(activity.data);
  const windowLabel = activityWindowLabel(hours);
  const [prefill, setPrefill] = useState<SyslogRulePrefill | null>(null);

  function createFrom(p: SyslogRulePrefill) {
    setPrefill(p);
    setCreating(true);
  }

  function change(rule: SyslogRule, data: { enabled?: boolean; severity?: SyslogSeverity }) {
    return pending.run(rule.key, async () => {
      try {
        if (rule.builtin) await patchBuiltin.mutateAsync({ key: rule.key, data });
        else if (rule.id != null) await updateCustom.mutateAsync({ id: rule.id, data });
      } catch (e) {
        void alert({ message: (e as Error).message, variant: 'error' });
      }
    });
  }

  async function handleDelete(rule: SyslogRule) {
    if (rule.id == null) return;
    const id = rule.id;
    const ok = await confirm({
      title: 'Delete syslog rule',
      message: `Delete rule '${rule.name}'? Its open alerts are resolved.`,
      confirmLabel: 'Delete',
    });
    if (!ok) return;
    await deleting.run(rule.key, async () => {
      try {
        await deleteMut.mutateAsync(id);
      } catch (e) {
        void alert({ message: (e as Error).message, variant: 'error' });
      }
    });
  }

  return (
    <div>
      <div className="toolbar" style={{ justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
        <span className="text-muted" style={{ fontSize: '0.85em' }}>
          Rules run on the server against syslog from inventory hosts and raise alerts under Monitoring → Alerts.
        </span>
        <button className="btn btn-primary" onClick={() => setCreating(true)}>+ New Syslog Rule</button>
      </div>

      {rules.error && !rules.data ? <QueryError what="syslog rules" query={rules} /> : rules.isPending && <LoadingState />}
      {rules.data && (rules.data.length === 0 ? (
        <EmptyState message="No syslog rules" />
      ) : (
        <DataTable aria-label="Syslog rules">
          <thead>
            <tr>
              <th>Rule</th>
              <th>Patterns</th>
              <th style={{ whiteSpace: 'nowrap' }}>Matched ({windowLabel})</th>
              <th style={{ whiteSpace: 'nowrap' }}>Last match</th>
              <th>Severity</th>
              <th>Threshold</th>
              <th>Auto-resolve</th>
              <th aria-label="Actions" />
            </tr>
          </thead>
          <tbody>
            {rules.data.map((r) => {
              const busy = pending.isPending(r.key);
              const counts = activity.data ? ruleMatchCounts(r, matchesByKey) : null;
              return (
                <tr key={r.key}>
                  <td style={{ opacity: r.enabled ? 1 : INACTIVE_OPACITY }}>
                    <strong>{r.name}</strong>
                    {r.builtin && <span className="text-muted" style={{ fontSize: '0.75em', marginLeft: '0.4rem' }}>built-in</span>}
                    {!r.enabled && <span className="text-muted" style={{ fontSize: '0.75em', marginLeft: '0.3rem' }}>(disabled)</span>}
                    {r.builtin && r.families.length > 0 && (
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
                        <span className="text-muted">{r.match_type}:</span> <code>{r.pattern}</code>
                        {r.clear_pattern && <div className="text-muted">Clears: <code>{r.clear_pattern}</code></div>}
                      </>
                    )}
                  </td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    {activity.isPending ? (
                      <LoadingState variant="inline" text="" />
                    ) : counts ? (
                      <>
                        <span title={counts.hosts ? `From ${countLabel(counts.hosts, 'host', 'hosts')}` : undefined}>{formatCount(counts.raised)}</span>
                        {counts.cleared != null && (
                          <div className="text-muted" style={{ fontSize: '0.8em' }}>Cleared {formatCount(counts.cleared)}</div>
                        )}
                      </>
                    ) : '-'}
                  </td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    {activity.isPending ? <LoadingState variant="inline" text="" /> : formatBackendDateTime(counts?.last_at)}
                  </td>
                  <td>
                    <label className="sr-only" htmlFor={`syslog-sev-${r.key}`}>Severity of {r.name}</label>
                    <select
                      id={`syslog-sev-${r.key}`}
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
                      {!r.builtin && <DeleteButton busy={deleting.isPending(r.key)} onClick={() => void handleDelete(r)} />}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </DataTable>
      ))}

      <SyslogActivitySection
        hours={hours}
        onHoursChange={setHours}
        activity={activity}
        rules={rules.data}
        onCreateRule={createFrom}
      />

      <SyslogRuleModal
        rule={editing}
        isCreate={creating}
        prefill={prefill}
        onClose={() => { setEditing(null); setCreating(false); setPrefill(null); }}
      />
    </div>
  );
}

// Create (rule == null, isCreate) or edit (rule set) a custom syslog rule,
// with a box to try the draft against a sample message. `prefill` fills a new
// rule from a received message ("Create rule" under Received messages).
function SyslogRuleModal({ rule, isCreate, prefill, onClose }: {
  rule: SyslogRule | null;
  isCreate: boolean;
  prefill: SyslogRulePrefill | null;
  onClose: () => void;
}) {
  const formId = useId();
  const isOpen = isCreate || rule != null;
  const createMut = useCreateSyslogRule();
  const updateMut = useUpdateSyslogRule();
  const testMut = useTestSyslogMessage();
  const [form, setForm] = useState<SyslogRuleForm>(EMPTY_SYSLOG_RULE_FORM);
  const [saveError, setSaveError] = useState('');
  const [sample, setSample] = useState('');

  // Load the form when the modal opens for another rule (or for a new one).
  const [prevRule, setPrevRule] = useState(rule);
  const [prevIsCreate, setPrevIsCreate] = useState(isCreate);
  const [prevPrefill, setPrevPrefill] = useState(prefill);
  if (rule !== prevRule || isCreate !== prevIsCreate || prefill !== prevPrefill) {
    setPrevRule(rule);
    setPrevIsCreate(isCreate);
    setPrevPrefill(prefill);
    setSaveError('');
    testMut.reset();
    setForm(rule ? formFromRule(rule) : prefill?.form ?? EMPTY_SYSLOG_RULE_FORM);
    // A rule made from a received message opens with that message in the tester.
    if (prefill) setSample(prefill.sample);
  }

  function set<K extends keyof SyslogRuleForm>(key: K, value: SyslogRuleForm[K]) {
    setForm((prev) => ({ ...prev, [key]: value }));
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSaveError('');
    const body = bodyFromForm(form);
    const onError = (err: Error) => setSaveError(err.message);
    if (rule?.id != null) updateMut.mutate({ id: rule.id, data: body }, { onSuccess: onClose, onError });
    else createMut.mutate(body, { onSuccess: onClose, onError });
  }

  function runTest() {
    const draft = bodyFromForm(form);
    testMut.mutate({ message: sample, rule: draft.name && draft.pattern ? draft : undefined });
  }

  const saving = createMut.isPending || updateMut.isPending;
  const hint = SYSLOG_MATCH_TYPES.find((t) => t.value === form.match_type)?.hint ?? '';
  const result = testMut.data;

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={rule ? 'Edit Syslog Rule' : 'Create Syslog Rule'}
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
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-name`}>Name</label>
          <input id={`${formId}-name`} className="form-input" value={form.name} onChange={(e) => set('name', e.target.value)} required maxLength={100} />
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <div className="form-group" style={{ flex: '1 1 10rem' }}>
            <label className="form-label" htmlFor={`${formId}-type`}>Match</label>
            <select id={`${formId}-type`} className="form-select" value={form.match_type} onChange={(e) => set('match_type', e.target.value as SyslogMatchType)}>
              {SYSLOG_MATCH_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
            </select>
          </div>
          <div className="form-group" style={{ flex: '1 1 10rem' }}>
            <label className="form-label" htmlFor={`${formId}-severity`}>Severity</label>
            <select id={`${formId}-severity`} className="form-select" value={form.severity} onChange={(e) => set('severity', e.target.value as SyslogSeverity)}>
              {SYSLOG_SEVERITY_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-pattern`}>Raise pattern</label>
          <input id={`${formId}-pattern`} className="form-input" value={form.pattern} onChange={(e) => set('pattern', e.target.value)} required maxLength={500} aria-describedby={`${formId}-hint`} />
          <div id={`${formId}-hint`} className="text-muted" style={{ fontSize: '0.78em', marginTop: '0.2rem' }}>{hint}</div>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-clear`}>Clear pattern (optional)</label>
          <input id={`${formId}-clear`} className="form-input" value={form.clear_pattern} onChange={(e) => set('clear_pattern', e.target.value)} maxLength={500} />
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <div className="form-group" style={{ flex: '1 1 8rem' }}>
            <label className="form-label" htmlFor={`${formId}-count`}>Matches to raise</label>
            <input id={`${formId}-count`} className="form-input" type="number" min="1" max="1000" value={form.threshold_count} onChange={(e) => set('threshold_count', e.target.value)} />
          </div>
          <div className="form-group" style={{ flex: '1 1 8rem' }}>
            <label className="form-label" htmlFor={`${formId}-window`}>Within (seconds)</label>
            <input id={`${formId}-window`} className="form-input" type="number" min="1" max="86400" value={form.threshold_window_seconds} onChange={(e) => set('threshold_window_seconds', e.target.value)} />
          </div>
          <div className="form-group" style={{ flex: '1 1 8rem' }}>
            <label className="form-label" htmlFor={`${formId}-resolve`}>Auto-resolve (min, 0 = off)</label>
            <input id={`${formId}-resolve`} className="form-input" type="number" min="0" max="10080" value={form.auto_resolve_minutes} onChange={(e) => set('auto_resolve_minutes', e.target.value)} />
          </div>
        </div>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.9em' }}>
          <input type="checkbox" checked={form.enabled} onChange={(e) => set('enabled', e.target.checked)} />
          Enabled
        </label>

        <div className="form-group" style={{ marginTop: '1rem' }}>
          <label className="form-label" htmlFor={`${formId}-sample`}>Test against a sample message</label>
          <textarea
            id={`${formId}-sample`}
            className="form-input"
            rows={2}
            value={sample}
            onChange={(e) => setSample(e.target.value)}
            placeholder="%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down"
          />
          <div style={{ marginTop: '0.4rem' }}>
            <BusyButton type="button" className="btn btn-sm btn-secondary" busy={testMut.isPending} disabled={!sample.trim()} onClick={runTest}>
              Test Message
            </BusyButton>
          </div>
        </div>
        {testMut.error && <Callout tone="danger">{testMut.error.message}</Callout>}
        {result && (
          <div className="card card-sm" style={{ fontSize: '0.85em' }} aria-live="polite">
            <div><span className="text-muted">Tag:</span> <code>{result.tag || '(none found)'}</code></div>
            {result.program && (
              <div><span className="text-muted">Program:</span> <code>{result.program}</code></div>
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
            {result.repoll && <div>{repollLabel(result.repoll)}</div>}
            {result.recollect && <div>{recollectLabel(result.recollect)}</div>}
          </div>
        )}
      </form>
    </Modal>
  );
}
