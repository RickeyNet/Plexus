// Pure helpers for external secrets providers (docs/secrets-providers.md):
// the provider form, which secret fields each auth method uses, and the
// external reference credentials and secret variables carry. The secret-field
// rules mirror `used_secrets` in netcontrol/secrets_providers/*.py.

export type ProviderType = 'vault' | 'aws' | 'azure';
export type ConfigValue = string | number | boolean;

export const PROVIDER_TYPES: ProviderType[] = ['vault', 'aws', 'azure'];

export const PROVIDER_TYPE_LABELS: Record<ProviderType, string> = {
  vault: 'HashiCorp Vault',
  aws: 'AWS Secrets Manager',
  azure: 'Azure Key Vault',
};

export const DEFAULT_CONFIG: Record<ProviderType, Record<string, ConfigValue>> = {
  vault: {
    url: '',
    mount: 'secret',
    kv_version: 2,
    auth_method: 'token',
    namespace: '',
    role_id: '',
    approle_mount: 'approle',
    verify_tls: true,
    ca_pem: '',
    timeout: 10,
  },
  aws: { region: '', access_key_id: '', role_arn: '', external_id: '', endpoint_url: '', timeout: 10 },
  azure: {
    vault_url: '',
    auth_method: 'client_secret',
    tenant_id: '',
    client_id: '',
    authority_host: 'https://login.microsoftonline.com',
    verify_tls: true,
    ca_pem: '',
    timeout: 10,
  },
};

export const SECRET_LABELS: Record<string, string> = {
  token: 'Vault token',
  secret_id: 'AppRole secret ID',
  secret_access_key: 'Secret access key',
  session_token: 'Session token (optional)',
  client_secret: 'Client secret',
};

/** The provider's own secrets its settings use; the server drops the rest. */
export function secretFieldsFor(type: ProviderType, config: Record<string, ConfigValue>): string[] {
  if (type === 'vault') return config.auth_method === 'approle' ? ['secret_id'] : ['token'];
  if (type === 'aws') return String(config.access_key_id ?? '').trim() ? ['secret_access_key', 'session_token'] : [];
  return config.auth_method === 'client_secret' ? ['client_secret'] : [];
}

/** Secrets the form must ask for (optional ones excluded). */
function requiredSecrets(type: ProviderType, config: Record<string, ConfigValue>): string[] {
  return secretFieldsFor(type, config).filter((s) => s !== 'session_token');
}

export interface ProviderForm {
  name: string;
  provider_type: ProviderType;
  description: string;
  enabled: boolean;
  allow_user_credentials: boolean;
  cache_ttl: number;
  config: Record<string, ConfigValue>;
  /** Typed secrets; blank keeps the stored value on edit. */
  secrets: Record<string, string>;
}

export interface StoredProvider {
  name: string;
  provider_type: string;
  description?: string;
  enabled: boolean;
  allow_user_credentials: boolean;
  cache_ttl: number;
  config: Record<string, ConfigValue>;
}

export function isProviderType(value: string): value is ProviderType {
  return (PROVIDER_TYPES as string[]).includes(value);
}

export function emptyProviderForm(type: ProviderType = 'vault'): ProviderForm {
  return {
    name: '',
    provider_type: type,
    description: '',
    enabled: true,
    allow_user_credentials: false,
    cache_ttl: 300,
    config: { ...DEFAULT_CONFIG[type] },
    secrets: {},
  };
}

export function toProviderForm(p: StoredProvider): ProviderForm {
  const type = isProviderType(p.provider_type) ? p.provider_type : 'vault';
  return {
    name: p.name,
    provider_type: type,
    description: p.description ?? '',
    enabled: p.enabled,
    allow_user_credentials: p.allow_user_credentials,
    cache_ttl: p.cache_ttl,
    config: { ...DEFAULT_CONFIG[type], ...p.config },
    secrets: {},
  };
}

export type ProviderFormErrors = Partial<Record<string, string>>;

const REQUIRED_SETTING: Record<ProviderType, [string, string][]> = {
  vault: [['url', 'Enter the Vault address']],
  aws: [['region', 'Enter the AWS region']],
  azure: [['vault_url', 'Enter the vault URL']],
};

function isHttpUrl(value: string): boolean {
  return /^https?:\/\/[^\s/]+/i.test(value);
}

/** Field errors keyed by `name`, `config.<setting>` or `secrets.<field>`. */
export function validateProviderForm(form: ProviderForm, storedSecrets: string[] = []): ProviderFormErrors {
  const errors: ProviderFormErrors = {};
  if (!form.name.trim()) errors.name = 'Enter a name';
  if (!Number.isInteger(form.cache_ttl) || form.cache_ttl < 0 || form.cache_ttl > 3600)
    errors.cache_ttl = 'Enter 0 to 3600 seconds';
  const type = form.provider_type;
  for (const [setting, message] of REQUIRED_SETTING[type]) {
    if (!String(form.config[setting] ?? '').trim()) errors[`config.${setting}`] = message;
  }
  for (const setting of ['url', 'vault_url', 'endpoint_url', 'authority_host']) {
    const value = String(form.config[setting] ?? '').trim();
    if (setting in DEFAULT_CONFIG[type] && value && !isHttpUrl(value))
      errors[`config.${setting}`] = 'Enter an http:// or https:// URL';
  }
  if (type === 'vault' && form.config.auth_method === 'approle' && !String(form.config.role_id ?? '').trim())
    errors['config.role_id'] = 'Enter the AppRole role ID';
  if (type === 'azure' && form.config.auth_method === 'client_secret') {
    if (!String(form.config.tenant_id ?? '').trim()) errors['config.tenant_id'] = 'Enter the tenant ID';
    if (!String(form.config.client_id ?? '').trim()) errors['config.client_id'] = 'Enter the client ID';
  }
  for (const secret of requiredSecrets(type, form.config)) {
    if (!form.secrets[secret] && !storedSecrets.includes(secret))
      errors[`secrets.${secret}`] = `Enter the ${SECRET_LABELS[secret].toLowerCase()}`;
  }
  return errors;
}

export interface ProviderPayload {
  name: string;
  provider_type: ProviderType;
  description: string;
  enabled: boolean;
  allow_user_credentials: boolean;
  cache_ttl: number;
  config: Record<string, ConfigValue>;
  secrets: Record<string, string>;
}

/** The request body: settings of the chosen type, and only the secrets that
 *  were typed and that the settings use (blank ones keep the stored value). */
export function providerPayload(form: ProviderForm): ProviderPayload {
  const type = form.provider_type;
  const config: Record<string, ConfigValue> = {};
  for (const key of Object.keys(DEFAULT_CONFIG[type])) {
    const value = form.config[key] ?? DEFAULT_CONFIG[type][key];
    config[key] = typeof value === 'string' ? value.trim() : value;
  }
  const secrets: Record<string, string> = {};
  for (const field of secretFieldsFor(type, config)) {
    if (form.secrets[field]) secrets[field] = form.secrets[field];
  }
  return {
    name: form.name.trim(),
    provider_type: type,
    description: form.description.trim(),
    enabled: form.enabled,
    allow_user_credentials: form.allow_user_credentials,
    cache_ttl: form.cache_ttl,
    config,
    secrets,
  };
}

/** The reference a credential or secret variable keeps instead of a value. */
export interface ReferenceDraft {
  provider_id: number | null;
  path: string;
  key: string;
  secret_key: string;
}

export interface ReferencedRow {
  ext_provider_id?: number | null;
  ext_provider_name?: string | null;
  ext_path?: string | null;
  ext_key?: string | null;
  ext_secret_key?: string | null;
}

export function hasReference(row: ReferencedRow | null | undefined): boolean {
  return row?.ext_provider_id != null;
}

export function referenceDraft(row: ReferencedRow | null | undefined): ReferenceDraft {
  return {
    provider_id: row?.ext_provider_id ?? null,
    path: row?.ext_path ?? '',
    key: row?.ext_key ?? '',
    secret_key: row?.ext_secret_key ?? '',
  };
}

/** The label of a provider type, or the raw value for an unknown one. */
export function providerTypeLabel(type: string): string {
  return isProviderType(type) ? PROVIDER_TYPE_LABELS[type] : type;
}

/** "corp-vault · network/core · password", or `null` without a reference. */
export function referenceLabel(row: ReferencedRow | null | undefined): string | null {
  if (!hasReference(row)) return null;
  const parts = [row?.ext_provider_name || `provider ${row?.ext_provider_id}`, row?.ext_path ?? ''];
  if (row?.ext_key) parts.push(row.ext_key);
  return parts.join(' · ');
}

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;

export type ReferenceErrors = Partial<Record<'provider' | 'path' | 'key', string>>;

/** Field errors of a reference draft (`provider`, `path`, `key`). */
export function validateReference(ref: ReferenceDraft): ReferenceErrors {
  const errors: ReferenceErrors = {};
  if (ref.provider_id == null) errors.provider = 'Choose a secrets provider';
  const path = ref.path.trim();
  if (!path) errors.path = 'Enter the path of the secret';
  else if (path.length > 512 || CONTROL_CHARS.test(path)) errors.path = 'Use at most 512 printable characters';
  if (ref.key.length > 256 || ref.secret_key.length > 256 || CONTROL_CHARS.test(ref.key + ref.secret_key))
    errors.key = 'Use at most 256 printable characters';
  return errors;
}

/** The `external` field of a credential or secret variable request. */
export interface ExternalReferenceBody {
  provider_id: number;
  path: string;
  key: string;
  /** Credentials only: the key of the enable secret (blank: the password). */
  secret_key?: string;
}

/** The `external` body field; `withSecretKey` for credentials only. */
export function referencePayload(ref: ReferenceDraft, withSecretKey = false): ExternalReferenceBody {
  const body: ExternalReferenceBody = {
    provider_id: ref.provider_id ?? 0,
    path: ref.path.trim(),
    key: ref.key.trim(),
  };
  if (withSecretKey) body.secret_key = ref.secret_key.trim();
  return body;
}

export function sameReference(a: ReferenceDraft, b: ReferenceDraft): boolean {
  return (
    a.provider_id === b.provider_id &&
    a.path.trim() === b.path.trim() &&
    a.key.trim() === b.key.trim() &&
    a.secret_key.trim() === b.secret_key.trim()
  );
}

/** Help shown under the path field, per provider type. */
export const PATH_HELP: Record<ProviderType, string> = {
  vault: 'Path under the mount, for example network/core-switches. The key names a field of the secret.',
  aws: 'Secret name or ARN. The key names a key of a JSON secret; leave it blank for the whole value.',
  azure: 'Secret name, optionally name/version. The key names a key of a JSON value; leave it blank for the whole value.',
};

const TEST_ERROR_HINTS: Record<string, string> = {
  sdk_not_installed: 'Install requirements-cloud.txt on the Plexus server.',
  auth_failed: 'Check the provider credentials.',
  forbidden: 'Grant the Plexus identity read access to this secret.',
  not_found: 'Check the path and mount.',
  key_not_found: 'Check the key name.',
  unreachable: 'Check the address, TLS settings and firewall.',
  disabled: 'Enable the provider first.',
};

/** The message of a failed test, with a next step when there is one. */
export function testFailureText(code: string, message: string): string {
  const hint = TEST_ERROR_HINTS[code];
  return hint ? `${message} ${hint}` : message;
}
