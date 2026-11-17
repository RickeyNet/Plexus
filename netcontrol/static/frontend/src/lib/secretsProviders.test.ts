import { describe, expect, it } from 'vitest';

import {
  emptyProviderForm,
  hasReference,
  providerPayload,
  providerTypeLabel,
  referenceDraft,
  referenceLabel,
  referencePayload,
  sameReference,
  secretFieldsFor,
  testFailureText,
  toProviderForm,
  validateProviderForm,
  validateReference,
} from './secretsProviders';

describe('secretFieldsFor', () => {
  it('follows the auth method like the server', () => {
    expect(secretFieldsFor('vault', { auth_method: 'token' })).toEqual(['token']);
    expect(secretFieldsFor('vault', { auth_method: 'approle' })).toEqual(['secret_id']);
    expect(secretFieldsFor('aws', { access_key_id: '' })).toEqual([]);
    expect(secretFieldsFor('aws', { access_key_id: 'test-key-id' })).toEqual(['secret_access_key', 'session_token']);
    expect(secretFieldsFor('azure', { auth_method: 'client_secret' })).toEqual(['client_secret']);
    expect(secretFieldsFor('azure', { auth_method: 'default' })).toEqual([]);
  });
});

describe('validateProviderForm', () => {
  it('requires the name, address and the secret the auth method uses', () => {
    const form = emptyProviderForm('vault');
    expect(validateProviderForm(form)).toMatchObject({
      name: 'Enter a name',
      'config.url': 'Enter the Vault address',
      'secrets.token': 'Enter the vault token',
    });
    const filled = { ...form, name: 'corp', config: { ...form.config, url: 'https://vault.example.com' } };
    expect(validateProviderForm(filled, ['token'])).toEqual({});
    expect(validateProviderForm({ ...filled, secrets: { token: 'x' } })).toEqual({});
  });

  it('checks URLs, AppRole, Azure ids and the cache range', () => {
    const vault = emptyProviderForm('vault');
    const errors = validateProviderForm({
      ...vault,
      name: 'v',
      cache_ttl: 5000,
      config: { ...vault.config, url: 'vault.example.com', auth_method: 'approle' },
    });
    expect(errors['config.url']).toMatch(/http/);
    expect(errors['config.role_id']).toBeDefined();
    expect(errors['secrets.secret_id']).toBeDefined();
    expect(errors.cache_ttl).toBeDefined();
    const azure = emptyProviderForm('azure');
    expect(validateProviderForm({ ...azure, name: 'a', config: { ...azure.config, vault_url: 'https://kv.example.com' } }))
      .toMatchObject({ 'config.tenant_id': 'Enter the tenant ID', 'config.client_id': 'Enter the client ID' });
    const aws = emptyProviderForm('aws');
    expect(validateProviderForm({ ...aws, name: 'a', config: { ...aws.config, region: 'us-east-1' } })).toEqual({});
  });
});

describe('providerPayload', () => {
  it('sends only the settings of the type and the typed secrets it uses', () => {
    const form = {
      ...emptyProviderForm('aws'),
      name: ' aws ',
      config: { ...emptyProviderForm('aws').config, region: ' eu-west-1 ', stray: 'x' },
      secrets: { secret_access_key: 'typed', client_secret: 'other' },
    };
    const body = providerPayload(form);
    expect(body.name).toBe('aws');
    expect(body.config.region).toBe('eu-west-1');
    expect(body.config).not.toHaveProperty('stray');
    // No access key id: the default chain, so no secret is sent.
    expect(body.secrets).toEqual({});
    const keyed = providerPayload({ ...form, config: { ...form.config, access_key_id: 'test-key-id' } });
    expect(keyed.secrets).toEqual({ secret_access_key: 'typed' });
  });

  it('round-trips a stored provider without its secrets', () => {
    const form = toProviderForm({
      name: 'corp',
      provider_type: 'vault',
      enabled: true,
      allow_user_credentials: false,
      cache_ttl: 60,
      config: { url: 'https://vault.example.com', kv_version: 1 },
    });
    expect(form.config).toMatchObject({ url: 'https://vault.example.com', kv_version: 1, mount: 'secret' });
    expect(form.secrets).toEqual({});
    expect(toProviderForm({ ...form, provider_type: 'unknown' }).provider_type).toBe('vault');
  });
});

describe('references', () => {
  const row = {
    ext_provider_id: 3,
    ext_provider_name: 'corp-vault',
    ext_path: 'network/core',
    ext_key: 'password',
    ext_secret_key: 'enable',
  };

  it('labels and drafts a reference', () => {
    expect(hasReference(row)).toBe(true);
    expect(hasReference({ ext_provider_id: null })).toBe(false);
    expect(referenceLabel(row)).toBe('corp-vault · network/core · password');
    expect(referenceLabel({ ext_provider_id: 4, ext_path: 'p' })).toBe('provider 4 · p');
    expect(referenceLabel(null)).toBeNull();
    expect(referenceDraft(row)).toEqual({ provider_id: 3, path: 'network/core', key: 'password', secret_key: 'enable' });
    expect(referenceDraft(undefined)).toEqual({ provider_id: null, path: '', key: '', secret_key: '' });
  });

  it('validates, compares and builds the request body', () => {
    expect(validateReference(referenceDraft(null))).toEqual({
      provider: 'Choose a secrets provider',
      path: 'Enter the path of the secret',
    });
    expect(validateReference({ provider_id: 1, path: 'a\nb', key: '', secret_key: '' }).path).toBeDefined();
    expect(validateReference({ provider_id: 1, path: 'p', key: 'k'.repeat(300), secret_key: '' }).key).toBeDefined();
    const draft = { provider_id: 3, path: ' network/core ', key: ' password ', secret_key: ' enable ' };
    expect(sameReference(draft, referenceDraft(row))).toBe(true);
    expect(sameReference({ ...draft, key: 'other' }, referenceDraft(row))).toBe(false);
    expect(referencePayload(draft)).toEqual({ provider_id: 3, path: 'network/core', key: 'password' });
    expect(referencePayload(draft, true)).toEqual({
      provider_id: 3,
      path: 'network/core',
      key: 'password',
      secret_key: 'enable',
    });
  });

  it('labels types and explains failures', () => {
    expect(providerTypeLabel('azure')).toBe('Azure Key Vault');
    expect(providerTypeLabel('other')).toBe('other');
    expect(testFailureText('not_found', 'No secret.')).toBe('No secret. Check the path and mount.');
    expect(testFailureText('provider_error', 'Failed.')).toBe('Failed.');
  });
});
