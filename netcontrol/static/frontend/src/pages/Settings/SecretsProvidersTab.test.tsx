import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { SecretsProvider } from '@/api/secretsProviders';

import { SecretsProvidersTab } from './SecretsProvidersTab';

const state = vi.hoisted(() => ({ role: 'admin', providers: [] as unknown[] }));

const mutation = { isPending: false, isError: false, data: undefined, mutate: () => {}, mutateAsync: async () => ({}) };

vi.mock('@/api/secretsProviders', () => ({
  useSecretsProviders: () => ({
    isError: false,
    isPending: false,
    data: { providers: state.providers, types: [] },
    error: null,
    refetch: () => {},
  }),
  useDeleteSecretsProvider: () => mutation,
  useTestSecretsProvider: () => mutation,
}));
vi.mock('@/api/auth', () => ({ useAuthStatus: () => ({ data: { role: state.role } }) }));
vi.mock('@/components/DialogProvider-context', () => ({
  useDialogs: () => ({ confirm: async () => true, alert: async () => {} }),
}));
vi.mock('./SecretsProviderModal', () => ({ SecretsProviderModal: () => null }));

const provider: SecretsProvider = {
  id: 1,
  name: 'lab-vault',
  provider_type: 'vault',
  description: '',
  enabled: true,
  allow_user_credentials: false,
  cache_ttl: 300,
  config: {},
  secrets_set: ['token'],
  credential_count: 0,
  secret_variable_count: 0,
  sdk: { status: 'ok', missing: [] },
};

const render = () => renderToStaticMarkup(<SecretsProvidersTab />);

describe('SecretsProvidersTab', () => {
  beforeEach(() => {
    state.role = 'admin';
    state.providers = [provider];
  });

  it('shows add, test, edit and delete to admins', () => {
    const html = render();
    expect(html).toContain('lab-vault');
    expect(html).toContain('Add secrets provider');
    expect(html).toContain('>Test<');
    expect(html).toContain('>Edit<');
    expect(html).toContain('Delete secrets provider lab-vault');
  });

  it('shows other users the list without any change or test control', () => {
    state.role = 'user';
    const html = render();
    expect(html).toContain('lab-vault');
    expect(html).not.toContain('Add secrets provider');
    expect(html).not.toContain('>Test<');
    expect(html).not.toContain('>Edit<');
    expect(html).not.toContain('Delete secrets provider');
    expect(html).not.toContain('Actions');
  });

  it('tells other users an admin adds providers when there are none', () => {
    state.role = 'user';
    state.providers = [];
    const html = render();
    expect(html).not.toContain('Add secrets provider');
    expect(html).toContain('An admin adds');
  });
});
