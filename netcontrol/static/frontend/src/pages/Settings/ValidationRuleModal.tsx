import { useId, useState } from 'react';

import { CustomDataError } from '@/api/customData';
import {
  type RuleFieldCatalogue,
  type RuleTestResult,
  type ValidationObjectType,
  type ValidationRule,
  type ValidationRuleType,
  useCreateValidationRule,
  useTestValidationRule,
  useUpdateValidationRule,
} from '@/api/validationRules';
import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';

import { CheckboxField } from './FormFields';
import {
  OBJECT_TYPE_LABEL,
  RULE_TYPE_HELP,
  RULE_TYPE_LABEL,
  type RuleDraft,
  type RuleDraftErrors,
  draftErrorsFromServer,
  emptyRuleDraft,
  fieldLabel,
  toRuleDraft,
  toRuleInput,
  toTestRequest,
  validateRuleDraft,
} from './validationRules';

type Field = keyof RuleDraftErrors;

interface Props {
  /** The rule to edit; `null` adds one. */
  rule: ValidationRule | null;
  catalogue: RuleFieldCatalogue;
  onClose: () => void;
}

/** Adds or edits a data validation rule, with a box to try a value against it before saving. */
export function ValidationRuleModal({ rule, catalogue, onClose }: Props) {
  const id = useId();
  const create = useCreateValidationRule();
  const update = useUpdateValidationRule();
  const tester = useTestValidationRule();
  const [draft, setDraft] = useState<RuleDraft>(() => (rule ? toRuleDraft(rule) : emptyRuleDraft()));
  const [touched, setTouched] = useState<Partial<Record<Field, boolean>>>({});
  const [serverErrors, setServerErrors] = useState<RuleDraftErrors>({});
  const [failure, setFailure] = useState<string | null>(null);
  const [sample, setSample] = useState('');
  const [result, setResult] = useState<RuleTestResult | null>(null);
  const [testError, setTestError] = useState<string | null>(null);

  const errors = validateRuleDraft(draft);
  const shown = (field: Field) => serverErrors[field] ?? (touched[field] ? errors[field] : undefined);
  const touch = (field: Field) => setTouched((t) => ({ ...t, [field]: true }));
  const set = (patch: Partial<RuleDraft>, cleared: Field[] = []) => {
    setDraft((d) => ({ ...d, ...patch }));
    setResult(null);
    if (cleared.length) setServerErrors((e) => Object.fromEntries(Object.entries(e).filter(([k]) => !cleared.includes(k as Field))));
  };
  const fields = catalogue.fields[draft.object_type] ?? [];
  const busy = create.isPending || update.isPending;
  const bounded = draft.rule_type === 'length' || draft.rule_type === 'numeric';

  const changeObjectType = (objectType: ValidationObjectType) => {
    const first = catalogue.fields[objectType]?.[0]?.field ?? '';
    set({ object_type: objectType, field: first }, ['field']);
  };

  const submit = () => {
    setTouched({ name: true, field: true, pattern: true, min: true, max: true, error_message: true });
    if (Object.keys(errors).length > 0) return;
    setFailure(null);
    const data = toRuleInput(draft);
    const done = {
      onSuccess: onClose,
      onError: (err: Error) => {
        if (err instanceof CustomDataError && Object.keys(err.fields).length > 0) {
          setServerErrors(draftErrorsFromServer(err.fields));
        }
        setFailure(err.message);
      },
    };
    if (rule) update.mutate({ id: rule.id, data }, done);
    else create.mutate(data, done);
  };

  const runTest = () => {
    setTestError(null);
    setResult(null);
    const problems = validateRuleDraft(draft);
    const ruleProblem = problems.pattern ?? problems.min ?? problems.max;
    if (ruleProblem) {
      setTouched((t) => ({ ...t, pattern: true, min: true, max: true }));
      return;
    }
    tester.mutate(toTestRequest(draft, sample), {
      onSuccess: setResult,
      onError: (err) => {
        if (err instanceof CustomDataError && Object.keys(err.fields).length > 0) {
          setServerErrors(draftErrorsFromServer(err.fields));
        } else {
          setTestError(`The value was not tested: ${err.message} Try again.`);
        }
      },
    });
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={rule ? `Edit rule ${rule.name}` : 'Add validation rule'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={rule ? 'Save rule' : 'Add rule'}
          primaryBusy={busy}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      {failure && (
        <Callout tone="danger" title="The rule was not saved">
          {failure} Check the fields and try again.
        </Callout>
      )}

      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-name`}>Name</label>
        <input
          id={`${id}-name`}
          className="form-input"
          value={draft.name}
          autoFocus
          aria-invalid={!!shown('name')}
          aria-describedby={`${id}-name-error`}
          onChange={(e) => set({ name: e.target.value }, ['name'])}
          onBlur={() => touch('name')}
        />
        <FieldError id={`${id}-name-error`}>{shown('name')}</FieldError>
      </div>

      <div className="form-row">
        <div className="form-group" style={{ flex: '1 1 12rem' }}>
          <label className="form-label" htmlFor={`${id}-object`}>Applies to</label>
          <select
            id={`${id}-object`}
            className="form-select"
            value={draft.object_type}
            onChange={(e) => changeObjectType(e.target.value as ValidationObjectType)}
          >
            {catalogue.object_types.map((t) => (
              <option key={t} value={t}>
                {OBJECT_TYPE_LABEL[t] ?? t}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group" style={{ flex: '1 1 12rem' }}>
          <label className="form-label" htmlFor={`${id}-field`}>Field</label>
          <select
            id={`${id}-field`}
            className="form-select"
            value={draft.field}
            aria-invalid={!!shown('field')}
            aria-describedby={`${id}-field-error`}
            onChange={(e) => set({ field: e.target.value }, ['field'])}
          >
            {!fields.some((f) => f.field === draft.field) && draft.field && (
              <option value={draft.field}>{fieldLabel(draft.field, fields)}</option>
            )}
            {fields.map((f) => (
              <option key={f.field} value={f.field}>
                {f.custom ? `${f.label} (custom field)` : `${f.label} (${f.field})`}
              </option>
            ))}
          </select>
          <FieldError id={`${id}-field-error`}>{shown('field')}</FieldError>
        </div>
      </div>

      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-type`}>Rule</label>
        <select
          id={`${id}-type`}
          className="form-select"
          value={draft.rule_type}
          aria-describedby={`${id}-type-help`}
          onChange={(e) => set({ rule_type: e.target.value as ValidationRuleType }, ['pattern', 'min', 'max'])}
        >
          {catalogue.rule_types.map((t) => (
            <option key={t} value={t}>
              {RULE_TYPE_LABEL[t] ?? t}
            </option>
          ))}
        </select>
        <div className="form-help" id={`${id}-type-help`}>
          {RULE_TYPE_HELP[draft.rule_type]}
          {draft.rule_type !== 'required' && ' An empty value passes; add a Required rule to forbid it.'}
        </div>
      </div>

      {draft.rule_type === 'regex' && (
        <div className="form-group">
          <label className="form-label" htmlFor={`${id}-pattern`}>Pattern</label>
          <input
            id={`${id}-pattern`}
            className="form-input"
            value={draft.pattern}
            spellCheck={false}
            placeholder="[a-z0-9-]+\.example\.com"
            aria-invalid={!!shown('pattern')}
            aria-describedby={`${id}-pattern-error`}
            onChange={(e) => set({ pattern: e.target.value }, ['pattern'])}
            onBlur={() => touch('pattern')}
          />
          <FieldError id={`${id}-pattern-error`}>{shown('pattern')}</FieldError>
        </div>
      )}

      {bounded && (
        <div className="form-row">
          {(['min', 'max'] as const).map((bound) => (
            <div className="form-group" style={{ flex: '0 1 10rem' }} key={bound}>
              <label className="form-label" htmlFor={`${id}-${bound}`}>
                {bound === 'min' ? 'Minimum' : 'Maximum'}
                {draft.rule_type === 'length' ? ' characters' : ''}
              </label>
              <input
                id={`${id}-${bound}`}
                className="form-input"
                inputMode={draft.rule_type === 'length' ? 'numeric' : 'decimal'}
                value={draft[bound]}
                aria-invalid={!!shown(bound)}
                aria-describedby={`${id}-${bound}-error`}
                onChange={(e) => set({ [bound]: e.target.value }, ['min', 'max'])}
                onBlur={() => touch(bound)}
              />
              <FieldError id={`${id}-${bound}-error`}>{shown(bound)}</FieldError>
            </div>
          ))}
        </div>
      )}

      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-message`}>Error message (optional)</label>
        <input
          id={`${id}-message`}
          className="form-input"
          value={draft.error_message}
          aria-invalid={!!shown('error_message')}
          aria-describedby={`${id}-message-help ${id}-message-error`}
          onChange={(e) => set({ error_message: e.target.value }, ['error_message'])}
          onBlur={() => touch('error_message')}
        />
        <div className="form-help" id={`${id}-message-help`}>
          Shown under the field when a value breaks the rule. Empty: a message is written for you.
        </div>
        <FieldError id={`${id}-message-error`}>{shown('error_message')}</FieldError>
      </div>

      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-description`}>Description (optional)</label>
        <textarea
          id={`${id}-description`}
          className="form-textarea"
          value={draft.description}
          onChange={(e) => set({ description: e.target.value })}
        />
      </div>

      <CheckboxField
        label="Enabled"
        checked={draft.enabled}
        onChange={(on) => set({ enabled: on })}
        help="Only enabled rules are checked when objects are saved."
      />

      <fieldset className="form-group" style={{ border: 0, padding: 0, margin: 0 }}>
        <legend className="form-label">Try a value</legend>
        <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'flex-start', flexWrap: 'wrap' }}>
          <input
            aria-label="Value to test"
            className="form-input"
            style={{ flex: '1 1 12rem' }}
            value={sample}
            spellCheck={false}
            onChange={(e) => {
              setSample(e.target.value);
              setResult(null);
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                runTest();
              }
            }}
          />
          <BusyButton className="btn btn-secondary" busy={tester.isPending} busyLabel="Testing…" onClick={runTest}>
            Test value
          </BusyButton>
        </div>
        <div aria-live="polite">
          {result &&
            (result.valid ? (
              <div className="form-help">The value passes this rule.</div>
            ) : (
              <FieldError>{`The value breaks this rule: ${result.message ?? ''}`}</FieldError>
            ))}
          <FieldError>{testError}</FieldError>
        </div>
      </fieldset>
    </Modal>
  );
}
