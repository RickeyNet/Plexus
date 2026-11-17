import { useId, useState } from 'react';

import {
  type SecretsProvider,
  useCreateSecretsProvider,
  useUpdateSecretsProvider,
} from '@/api/secretsProviders';
import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { SecretInput } from '@/components/SecretInput';
import {
  type ConfigValue,
  emptyProviderForm,
  PROVIDER_TYPE_LABELS,
  PROVIDER_TYPES,
  type ProviderForm,
  type ProviderType,
  providerPayload,
  SECRET_LABELS,
  secretFieldsFor,
  toProviderForm,
  validateProviderForm,
} from '@/lib/secretsProviders';

import { CheckboxField, CheckboxRow, FormRow } from './FormFields';

interface SettingSpec {
  name: string;
  label: string;
  kind?: 'text' | 'url' | 'select' | 'bool' | 'number' | 'pem';
  options?: { value: ConfigValue; label: string }[];
  help?: string;
  placeholder?: string;
  /** Shown only when this returns true for the current settings. */
  when?: (config: Record<string, ConfigValue>) => boolean;
}

const TLS: SettingSpec[] = [
  { name: 'verify_tls', label: 'Verify the TLS certificate', kind: 'bool' },
  {
    name: 'ca_pem',
    label: 'CA bundle (PEM, optional)',
    kind: 'pem',
    help: 'Trust only these certificates instead of the system store, for an internal CA.',
  },
];

const SETTINGS: Record<ProviderType, SettingSpec[]> = {
  vault: [
    { name: 'url', label: 'Vault address', kind: 'url', placeholder: 'https://vault.example.com:8200' },
    { name: 'mount', label: 'KV mount', placeholder: 'secret' },
    {
      name: 'kv_version',
      label: 'KV version',
      kind: 'select',
      options: [
        { value: 2, label: 'Version 2' },
        { value: 1, label: 'Version 1' },
      ],
    },
    { name: 'namespace', label: 'Namespace (Enterprise, optional)' },
    {
      name: 'auth_method',
      label: 'Authentication',
      kind: 'select',
      options: [
        { value: 'token', label: 'Token' },
        { value: 'approle', label: 'AppRole' },
      ],
    },
    { name: 'role_id', label: 'AppRole role ID', when: (c) => c.auth_method === 'approle' },
    { name: 'approle_mount', label: 'AppRole mount', when: (c) => c.auth_method === 'approle' },
    ...TLS,
  ],
  aws: [
    { name: 'region', label: 'Region', placeholder: 'us-east-1' },
    {
      name: 'access_key_id',
      label: 'Access key ID (optional)',
      help: 'Blank: the default credential chain of the Plexus server (instance or task role, environment).',
    },
    { name: 'role_arn', label: 'Role ARN to assume (optional)' },
    { name: 'external_id', label: 'External ID (optional)', when: (c) => !!String(c.role_arn ?? '').trim() },
    { name: 'endpoint_url', label: 'Endpoint URL (optional, VPC endpoint)', kind: 'url' },
  ],
  azure: [
    { name: 'vault_url', label: 'Vault URL', kind: 'url', placeholder: 'https://my-vault.vault.azure.net' },
    {
      name: 'auth_method',
      label: 'Authentication',
      kind: 'select',
      options: [
        { value: 'client_secret', label: 'App registration (client secret)' },
        { value: 'default', label: 'Managed identity / environment (azure-identity)' },
      ],
    },
    { name: 'tenant_id', label: 'Tenant ID', when: (c) => c.auth_method === 'client_secret' },
    { name: 'client_id', label: 'Client ID', when: (c) => c.auth_method === 'client_secret' },
    { name: 'authority_host', label: 'Authority host', kind: 'url', when: (c) => c.auth_method === 'client_secret' },
    ...TLS,
  ],
};

interface SecretsProviderModalProps {
  /** The provider to edit; `null` adds one. */
  provider: SecretsProvider | null;
  onClose: () => void;
}

/** Adds or edits a secrets provider. Its own secrets are write-only. */
export function SecretsProviderModal({ provider, onClose }: SecretsProviderModalProps) {
  const id = useId();
  const create = useCreateSecretsProvider();
  const update = useUpdateSecretsProvider();
  const [form, setForm] = useState<ProviderForm>(() => (provider ? toProviderForm(provider) : emptyProviderForm()));
  const [touched, setTouched] = useState<Record<string, boolean>>({});
  const [submitted, setSubmitted] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  const stored = provider?.secrets_set ?? [];
  const errors = validateProviderForm(form, stored);
  const shown = (field: string) => (submitted || touched[field] ? errors[field] : undefined);
  const touch = (field: string) => setTouched((t) => ({ ...t, [field]: true }));
  const set = (patch: Partial<ProviderForm>) => setForm((f) => ({ ...f, ...patch }));
  const setConfig = (name: string, value: ConfigValue) => setForm((f) => ({ ...f, config: { ...f.config, [name]: value } }));
  const setSecret = (name: string, value: string) => setForm((f) => ({ ...f, secrets: { ...f.secrets, [name]: value } }));
  const busy = create.isPending || update.isPending;

  const submit = () => {
    setSubmitted(true);
    if (Object.keys(errors).length > 0) return;
    setFailure(null);
    const body = providerPayload(form);
    const done = { onSuccess: onClose, onError: (e: Error) => setFailure(e.message) };
    if (provider) update.mutate({ id: provider.id, body }, done);
    else create.mutate(body, done);
  };

  const renderSetting = (spec: SettingSpec) => {
    const fid = `${id}-${spec.name}`;
    const key = `config.${spec.name}`;
    const value = form.config[spec.name];
    if (spec.kind === 'bool') {
      return (
        <CheckboxField key={spec.name} label={spec.label} checked={value === true} onChange={(v) => setConfig(spec.name, v)} />
      );
    }
    let control;
    if (spec.kind === 'select') {
      control = (
        <select
          id={fid}
          className="form-select"
          value={String(value)}
          onChange={(e) => {
            const match = spec.options?.find((o) => String(o.value) === e.target.value);
            setConfig(spec.name, match ? match.value : e.target.value);
          }}
        >
          {spec.options?.map((o) => (
            <option key={String(o.value)} value={String(o.value)}>
              {o.label}
            </option>
          ))}
        </select>
      );
    } else if (spec.kind === 'pem') {
      control = (
        <textarea
          id={fid}
          className="form-textarea"
          rows={4}
          value={String(value ?? '')}
          onChange={(e) => setConfig(spec.name, e.target.value)}
          spellCheck={false}
          aria-describedby={spec.help ? `${fid}-help` : undefined}
          placeholder="-----BEGIN CERTIFICATE-----"
        />
      );
    } else {
      control = (
        <input
          id={fid}
          className="form-input"
          value={String(value ?? '')}
          onChange={(e) => setConfig(spec.name, e.target.value)}
          onBlur={() => touch(key)}
          placeholder={spec.placeholder}
          aria-invalid={!!shown(key)}
          aria-describedby={spec.help ? `${fid}-help` : undefined}
          autoComplete="off"
          spellCheck={false}
        />
      );
    }
    return (
      <div className="form-group" key={spec.name}>
        <label className="form-label" htmlFor={fid}>
          {spec.label}
        </label>
        {control}
        {spec.help && (
          <div className="form-help" id={`${fid}-help`}>
            {spec.help}
          </div>
        )}
        <FieldError>{shown(key)}</FieldError>
      </div>
    );
  };

  const visible = SETTINGS[form.provider_type].filter((s) => !s.when || s.when(form.config));
  const secrets = secretFieldsFor(form.provider_type, form.config);

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={provider ? `Edit secrets provider: ${provider.name}` : 'Add secrets provider'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={provider ? 'Save provider' : 'Add provider'}
          primaryBusy={busy}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        {failure && <Callout tone="danger">{failure}</Callout>}
        <FormRow>
          <div className="form-group" style={{ flex: '1 1 220px' }}>
            <label className="form-label" htmlFor={`${id}-name`}>
              Name
            </label>
            <input
              id={`${id}-name`}
              className="form-input"
              value={form.name}
              onChange={(e) => set({ name: e.target.value })}
              onBlur={() => touch('name')}
              aria-invalid={!!shown('name')}
              autoComplete="off"
            />
            <FieldError>{shown('name')}</FieldError>
          </div>
          <div className="form-group" style={{ flex: '1 1 220px' }}>
            <label className="form-label" htmlFor={`${id}-type`}>
              Type
            </label>
            <select
              id={`${id}-type`}
              className="form-select"
              value={form.provider_type}
              disabled={provider !== null}
              onChange={(e) => {
                const next = emptyProviderForm(e.target.value as ProviderType);
                set({ provider_type: next.provider_type, config: next.config, secrets: {} });
              }}
            >
              {PROVIDER_TYPES.map((t) => (
                <option key={t} value={t}>
                  {PROVIDER_TYPE_LABELS[t]}
                </option>
              ))}
            </select>
          </div>
        </FormRow>
        <div className="form-group">
          <label className="form-label" htmlFor={`${id}-description`}>
            Description (optional)
          </label>
          <input
            id={`${id}-description`}
            className="form-input"
            value={form.description}
            onChange={(e) => set({ description: e.target.value })}
          />
        </div>
        {visible.map(renderSetting)}
        {secrets.map((field) => {
          const key = `secrets.${field}`;
          const has = stored.includes(field);
          return (
            <div className="form-group" key={field}>
              <label className="form-label" htmlFor={`${id}-secret-${field}`}>
                {SECRET_LABELS[field]}
              </label>
              <SecretInput
                id={`${id}-secret-${field}`}
                label={SECRET_LABELS[field]}
                value={form.secrets[field] ?? ''}
                onChange={(v) => setSecret(field, v)}
                onBlur={() => touch(key)}
                invalid={!!shown(key)}
                placeholder={has ? 'Stored; leave blank to keep' : undefined}
              />
              <FieldError>{shown(key)}</FieldError>
            </div>
          );
        })}
        <FormRow>
          <div className="form-group" style={{ flex: '0 1 220px' }}>
            <label className="form-label" htmlFor={`${id}-ttl`}>
              Cache values for (seconds)
            </label>
            <input
              id={`${id}-ttl`}
              className="form-input"
              type="number"
              min={0}
              max={3600}
              value={form.cache_ttl}
              onChange={(e) => set({ cache_ttl: Number(e.target.value) })}
              aria-invalid={!!shown('cache_ttl')}
              aria-describedby={`${id}-ttl-help`}
            />
            <div className="form-help" id={`${id}-ttl-help`}>
              In server memory only; 0 asks the provider every time.
            </div>
            <FieldError>{shown('cache_ttl')}</FieldError>
          </div>
        </FormRow>
        <CheckboxRow>
          <CheckboxField label="Enabled" checked={form.enabled} onChange={(v) => set({ enabled: v })} />
          <CheckboxField
            label="Allow personal credentials"
            checked={form.allow_user_credentials}
            onChange={(v) => set({ allow_user_credentials: v })}
            help="Non-admin users may point their own credentials at this provider, with its access."
          />
        </CheckboxRow>
        <button type="submit" hidden />
      </form>
    </Modal>
  );
}
