import { useOrgSites, useTenants } from '@/api/organization';
import { type ScopeRule, useObjectScopeModels } from '@/api/settings';

/** A rule row while being edited: the value may not be picked yet. */
export type DraftRule = Omit<ScopeRule, 'value_id'> & { value_id: number | null };

interface Props {
  rules: DraftRule[];
  onChange: (rules: DraftRule[]) => void;
}

const ANY_MODEL = '*';

/**
 * The scope rules of an access group limited to selected inventory groups:
 * records of one type (or every type) whose tenant or site is the chosen
 * one, read only or read and write. Saved with the access group.
 */
export function ScopeRulesEditor({ rules, onChange }: Props) {
  const models = useObjectScopeModels();
  const tenants = useTenants();
  const sites = useOrgSites();

  const modelChoices = (models.data ?? []).filter((m) => m.rule_attributes.length > 0);
  const attributesOf = (model: string): ('tenant' | 'site')[] =>
    model === ANY_MODEL
      ? ['tenant', 'site']
      : (modelChoices.find((m) => m.name === model)?.rule_attributes ?? ['tenant', 'site']);
  const valuesOf = (attribute: 'tenant' | 'site') =>
    attribute === 'tenant'
      ? (tenants.data ?? []).map((t) => ({ id: t.id, name: t.name }))
      : (sites.data ?? []).map((s) => ({ id: s.id, name: s.name }));

  const update = (index: number, patch: Partial<DraftRule>) => {
    const next = rules.map((r, i) => (i === index ? { ...r, ...patch } : r));
    onChange(next);
  };

  return (
    <div style={{ display: 'grid', rowGap: '0.35rem' }}>
      {rules.length === 0 && <div className="form-help">No scope rules.</div>}
      {rules.map((rule, index) => {
        const attributes = attributesOf(rule.model);
        return (
          <div key={index} style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', alignItems: 'center' }}>
            <select
              className="form-select form-select-sm"
              style={{ maxWidth: 190 }}
              aria-label={`Rule ${index + 1} record type`}
              value={rule.model}
              onChange={(e) => {
                const model = e.target.value;
                const allowed = attributesOf(model);
                update(index, {
                  model,
                  attribute: allowed.includes(rule.attribute) ? rule.attribute : allowed[0],
                  value_id: allowed.includes(rule.attribute) ? rule.value_id : null,
                });
              }}
            >
              <option value={ANY_MODEL}>Every record type</option>
              {modelChoices.map((m) => (
                <option key={m.name} value={m.name}>
                  {m.description || m.name}
                </option>
              ))}
            </select>
            <select
              className="form-select form-select-sm"
              style={{ maxWidth: 100 }}
              aria-label={`Rule ${index + 1} filter`}
              value={rule.attribute}
              onChange={(e) => update(index, { attribute: e.target.value as 'tenant' | 'site', value_id: null })}
            >
              {attributes.map((a) => (
                <option key={a} value={a}>
                  {a === 'tenant' ? 'Tenant' : 'Site'}
                </option>
              ))}
            </select>
            <select
              className="form-select form-select-sm"
              style={{ maxWidth: 180 }}
              aria-label={`Rule ${index + 1} ${rule.attribute}`}
              value={rule.value_id ?? ''}
              onChange={(e) => update(index, { value_id: e.target.value ? Number(e.target.value) : null })}
            >
              <option value="">Choose…</option>
              {valuesOf(rule.attribute).map((v) => (
                <option key={v.id} value={v.id}>
                  {v.name}
                </option>
              ))}
            </select>
            <select
              className="form-select form-select-sm"
              style={{ maxWidth: 150 }}
              aria-label={`Rule ${index + 1} access`}
              value={rule.can_write ? 'write' : 'read'}
              onChange={(e) => update(index, { can_write: e.target.value === 'write' })}
            >
              <option value="read">Read</option>
              <option value="write">Read and write</option>
            </select>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              aria-label={`Remove rule ${index + 1}`}
              onClick={() => onChange(rules.filter((_, i) => i !== index))}
            >
              Remove
            </button>
          </div>
        );
      })}
      <div>
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          onClick={() => onChange([...rules, { model: ANY_MODEL, attribute: 'tenant', value_id: null, can_write: false }])}
        >
          Add scope rule
        </button>
      </div>
    </div>
  );
}
