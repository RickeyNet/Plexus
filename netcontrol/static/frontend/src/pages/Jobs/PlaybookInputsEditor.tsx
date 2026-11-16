import { useId } from 'react';

import { FieldError } from '@/components/FieldError';
import type { AccessGroup } from '@/api/settings';
import type { JobPermissionRule, JobPermissions } from '@/api/jobs';

import {
  emptyRow,
  hasChoices,
  hasPattern,
  isBounded,
  JOB_INPUT_TYPES,
  type SchemaRow,
} from './jobInputs';

// ── Input schema editor ────────────────────────────────────────────────────

interface SchemaEditorProps {
  rows: SchemaRow[];
  onChange: (rows: SchemaRow[]) => void;
  /** Messages keyed `"<index>.<attr>"`. */
  errors: Record<string, string>;
  /** Where the loaded schema came from; `code` means the task's class declares it. */
  source?: 'stored' | 'code' | 'none';
}

/** Edits the typed inputs the run dialog asks for: one block per field. */
export function InputSchemaEditor({ rows, onChange, errors, source }: SchemaEditorProps) {
  const fid = useId();

  function update(i: number, patch: Partial<SchemaRow>) {
    onChange(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  }
  function move(i: number, by: number) {
    const next = [...rows];
    const [row] = next.splice(i, 1);
    next.splice(i + by, 0, row);
    onChange(next);
  }

  return (
    <div className="form-group" role="group" aria-labelledby={`${fid}-title`}>
      <span className="form-label" id={`${fid}-title`}>Run inputs</span>
      <div className="form-help">
        {source === 'code'
          ? 'These inputs are declared in the task code. Changing them here saves a copy that overrides the code; remove every field to go back to the code version.'
          : 'Fields the run dialog asks for. Their values reach the task as inputs (Python: self.inputs; Ansible: extra vars).'}
      </div>
      {rows.map((row, i) => {
        const err = (attr: string) => errors[`${i}.${attr}`];
        const id = (attr: string) => `${fid}-${i}-${attr}`;
        return (
          <fieldset key={i} style={{ border: '1px solid var(--border)', borderRadius: 6, padding: '0.75rem', margin: '0.5rem 0' }}>
            <legend style={{ padding: '0 0.25rem' }}>{row.label || row.name || `Field ${i + 1}`}</legend>
            <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
              <div className="form-group" style={{ flex: '1 1 160px' }}>
                <label className="form-label" htmlFor={id('name')}>Name</label>
                <input
                  id={id('name')}
                  className="form-input"
                  value={row.name}
                  aria-invalid={!!err('name')}
                  onChange={(e) => update(i, { name: e.target.value })}
                />
                <FieldError>{err('name')}</FieldError>
              </div>
              <div className="form-group" style={{ flex: '1 1 160px' }}>
                <label className="form-label" htmlFor={id('label')}>Label</label>
                <input id={id('label')} className="form-input" value={row.label} onChange={(e) => update(i, { label: e.target.value })} />
                <FieldError>{err('label')}</FieldError>
              </div>
              <div className="form-group" style={{ flex: '1 1 160px' }}>
                <label className="form-label" htmlFor={id('type')}>Type</label>
                <select
                  id={id('type')}
                  className="form-select"
                  value={row.type}
                  aria-invalid={!!err('type')}
                  onChange={(e) => update(i, { type: e.target.value as SchemaRow['type'] })}
                >
                  {JOB_INPUT_TYPES.map((t) => (
                    <option key={t.value} value={t.value}>{t.label}</option>
                  ))}
                </select>
                <FieldError>{err('type')}</FieldError>
              </div>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor={id('help')}>Help text</label>
              <input id={id('help')} className="form-input" value={row.help} onChange={(e) => update(i, { help: e.target.value })} />
              <FieldError>{err('help')}</FieldError>
            </div>
            <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
              {row.type !== 'host' && row.type !== 'group' && (
                <div className="form-group" style={{ flex: '1 1 160px' }}>
                  <label className="form-label" htmlFor={id('default')}>Default</label>
                  {row.type === 'boolean' ? (
                    <select id={id('default')} className="form-select" value={row.default} onChange={(e) => update(i, { default: e.target.value })}>
                      <option value="">No</option>
                      <option value="true">Yes</option>
                    </select>
                  ) : (
                    <input
                      id={id('default')}
                      className="form-input"
                      value={row.default}
                      aria-invalid={!!err('default')}
                      onChange={(e) => update(i, { default: e.target.value })}
                    />
                  )}
                  <FieldError>{err('default')}</FieldError>
                </div>
              )}
              {hasChoices(row.type) && (
                <div className="form-group" style={{ flex: '2 1 240px' }}>
                  <label className="form-label" htmlFor={id('choices')}>Choices (comma-separated)</label>
                  <input
                    id={id('choices')}
                    className="form-input"
                    value={row.choices}
                    aria-invalid={!!err('choices')}
                    onChange={(e) => update(i, { choices: e.target.value })}
                  />
                  <FieldError>{err('choices')}</FieldError>
                </div>
              )}
              {isBounded(row.type) && (
                <>
                  <div className="form-group" style={{ flex: '1 1 100px' }}>
                    <label className="form-label" htmlFor={id('min')}>{row.type === 'integer' ? 'Min value' : row.type === 'string' || row.type === 'text' ? 'Min length' : 'Min items'}</label>
                    <input id={id('min')} className="form-input" inputMode="numeric" value={row.min} aria-invalid={!!err('min')} onChange={(e) => update(i, { min: e.target.value })} />
                    <FieldError>{err('min')}</FieldError>
                  </div>
                  <div className="form-group" style={{ flex: '1 1 100px' }}>
                    <label className="form-label" htmlFor={id('max')}>{row.type === 'integer' ? 'Max value' : row.type === 'string' || row.type === 'text' ? 'Max length' : 'Max items'}</label>
                    <input id={id('max')} className="form-input" inputMode="numeric" value={row.max} aria-invalid={!!err('max')} onChange={(e) => update(i, { max: e.target.value })} />
                    <FieldError>{err('max')}</FieldError>
                  </div>
                </>
              )}
              {hasPattern(row.type) && (
                <div className="form-group" style={{ flex: '2 1 200px' }}>
                  <label className="form-label" htmlFor={id('regex')}>Pattern (regular expression)</label>
                  <input
                    id={id('regex')}
                    className="form-input"
                    value={row.regex}
                    aria-invalid={!!err('regex')}
                    placeholder="[a-z0-9-]+"
                    onChange={(e) => update(i, { regex: e.target.value })}
                  />
                  <FieldError>{err('regex')}</FieldError>
                </div>
              )}
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
              <label className="form-check" style={{ marginRight: 'auto' }}>
                <input type="checkbox" checked={row.required} onChange={(e) => update(i, { required: e.target.checked })} />
                <span>Required</span>
              </label>
              <button type="button" className="btn btn-sm btn-secondary" disabled={i === 0} onClick={() => move(i, -1)}>Move up</button>
              <button type="button" className="btn btn-sm btn-secondary" disabled={i === rows.length - 1} onClick={() => move(i, 1)}>Move down</button>
              <button type="button" className="btn btn-sm btn-secondary" onClick={() => onChange(rows.filter((_, j) => j !== i))}>Remove field</button>
            </div>
          </fieldset>
        );
      })}
      <button type="button" className="btn btn-sm btn-secondary" onClick={() => onChange([...rows, emptyRow()])}>
        Add field
      </button>
    </div>
  );
}

// ── Run / commit permissions (admin only) ──────────────────────────────────

interface PermissionsEditorProps {
  value: JobPermissions;
  onChange: (value: JobPermissions) => void;
  accessGroups: AccessGroup[] | undefined;
  accessGroupsFailed: boolean;
}

const ACTIONS: { key: keyof JobPermissions; title: string; help: string }[] = [
  { key: 'run', title: 'Who may run', help: 'Nothing ticked: everyone with the jobs feature. Admins are always allowed.' },
  { key: 'commit', title: 'Who may commit changes', help: 'Nothing ticked: the same people who may run. Others can only run a dry run.' },
];

/** Run and commit permission rules: the user role and access groups allowed. */
export function JobPermissionsEditor({ value, onChange, accessGroups, accessGroupsFailed }: PermissionsEditorProps) {
  const fid = useId();

  function toggle(action: keyof JobPermissions, kind: keyof JobPermissionRule, item: string | number, on: boolean) {
    const rule = value[action];
    const list = rule[kind] as (string | number)[];
    const next = on ? [...list, item] : list.filter((x) => x !== item);
    onChange({ ...value, [action]: { ...rule, [kind]: next } });
  }

  return (
    <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
      {ACTIONS.map(({ key, title, help }) => (
        <div key={key} className="form-group" role="group" aria-labelledby={`${fid}-${key}`} style={{ flex: '1 1 240px' }}>
          <span className="form-label" id={`${fid}-${key}`}>{title}</span>
          <label className="form-check">
            <input
              type="checkbox"
              checked={value[key].roles.includes('user')}
              onChange={(e) => toggle(key, 'roles', 'user', e.target.checked)}
            />
            <span>Every user (role: user)</span>
          </label>
          {(accessGroups ?? []).map((g) => (
            <label key={g.id} className="form-check">
              <input
                type="checkbox"
                checked={value[key].groups.includes(g.id)}
                onChange={(e) => toggle(key, 'groups', g.id, e.target.checked)}
              />
              <span>Access group: {g.name}</span>
            </label>
          ))}
          {accessGroupsFailed && <div className="form-help">Access groups could not be loaded.</div>}
          <div className="form-help">{help}</div>
        </div>
      ))}
    </div>
  );
}
