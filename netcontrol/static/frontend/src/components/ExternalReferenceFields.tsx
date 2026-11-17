import type { ReferenceProvider } from '@/api/secretsProviders';
import { FieldError } from '@/components/FieldError';
import { SegmentedControl } from '@/components/SegmentedControl';
import {
  isProviderType,
  PATH_HELP,
  providerTypeLabel,
  type ReferenceDraft,
  type ReferenceErrors,
} from '@/lib/secretsProviders';

export type ValueSource = 'stored' | 'external';

const SOURCE_OPTIONS = [
  { key: 'stored' as const, label: 'Stored in Plexus' },
  { key: 'external' as const, label: 'External reference' },
];

/** Stored value or external reference: the toggle above a secret's fields. */
export function ValueSourceToggle({
  value,
  onChange,
}: {
  value: ValueSource;
  onChange: (next: ValueSource) => void;
}) {
  return (
    <div className="form-group">
      <SegmentedControl options={SOURCE_OPTIONS} value={value} onChange={onChange} aria-label="Where the secret is kept" />
    </div>
  );
}

interface ExternalReferenceFieldsProps {
  idPrefix: string;
  value: ReferenceDraft;
  onChange: (next: ReferenceDraft) => void;
  providers: ReferenceProvider[];
  errors?: ReferenceErrors;
  onBlur?: (field: 'provider' | 'path' | 'key') => void;
  /** Credentials: a second key for the enable secret. */
  withSecretKey?: boolean;
  keyLabel?: string;
}

/**
 * Provider, path and key of a secret kept in an external secrets provider
 * (docs/secrets-providers.md). Plexus stores only this reference and reads
 * the value when it is used; the value never reaches the browser.
 */
export function ExternalReferenceFields({
  idPrefix,
  value,
  onChange,
  providers,
  errors = {},
  onBlur,
  withSecretKey = false,
  keyLabel = 'Key',
}: ExternalReferenceFieldsProps) {
  const set = (patch: Partial<ReferenceDraft>) => onChange({ ...value, ...patch });
  const chosen = providers.find((p) => p.id === value.provider_id);
  const type = chosen && isProviderType(chosen.provider_type) ? chosen.provider_type : null;
  // A reference to a provider the caller can no longer pick (disabled, or
  // not open to personal credentials) still shows by id.
  const options =
    value.provider_id != null && !chosen
      ? [...providers, { id: value.provider_id, name: `Provider ${value.provider_id}`, provider_type: '' }]
      : providers;

  return (
    <>
      <div className="form-group">
        <label className="form-label" htmlFor={`${idPrefix}-provider`}>
          Secrets provider
        </label>
        <select
          id={`${idPrefix}-provider`}
          className="form-select"
          value={value.provider_id ?? ''}
          onChange={(e) => set({ provider_id: e.target.value ? Number(e.target.value) : null })}
          onBlur={() => onBlur?.('provider')}
          aria-invalid={!!errors.provider}
        >
          <option value="">Choose a provider…</option>
          {options.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
              {p.provider_type ? ` (${providerTypeLabel(p.provider_type)})` : ''}
            </option>
          ))}
        </select>
        <FieldError>{errors.provider}</FieldError>
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor={`${idPrefix}-path`}>
          Path
        </label>
        <input
          id={`${idPrefix}-path`}
          className="form-input"
          value={value.path}
          onChange={(e) => set({ path: e.target.value })}
          onBlur={() => onBlur?.('path')}
          aria-invalid={!!errors.path}
          aria-describedby={`${idPrefix}-path-help`}
          autoComplete="off"
          spellCheck={false}
        />
        <div className="form-help" id={`${idPrefix}-path-help`}>
          {type ? PATH_HELP[type] : 'Where the secret lives in the provider.'}
        </div>
        <FieldError>{errors.path}</FieldError>
      </div>
      <div className="form-row">
        <div className="form-group" style={{ flex: '1 1 200px' }}>
          <label className="form-label" htmlFor={`${idPrefix}-key`}>
            {keyLabel}
          </label>
          <input
            id={`${idPrefix}-key`}
            className="form-input"
            value={value.key}
            onChange={(e) => set({ key: e.target.value })}
            onBlur={() => onBlur?.('key')}
            aria-invalid={!!errors.key}
            placeholder="e.g. password"
            autoComplete="off"
            spellCheck={false}
          />
        </div>
        {withSecretKey && (
          <div className="form-group" style={{ flex: '1 1 200px' }}>
            <label className="form-label" htmlFor={`${idPrefix}-secret-key`}>
              Enable secret key (optional)
            </label>
            <input
              id={`${idPrefix}-secret-key`}
              className="form-input"
              value={value.secret_key}
              onChange={(e) => set({ secret_key: e.target.value })}
              aria-describedby={`${idPrefix}-secret-key-help`}
              autoComplete="off"
              spellCheck={false}
            />
            <div className="form-help" id={`${idPrefix}-secret-key-help`}>
              Blank: the enable secret is the password.
            </div>
          </div>
        )}
      </div>
      <FieldError>{errors.key}</FieldError>
    </>
  );
}
