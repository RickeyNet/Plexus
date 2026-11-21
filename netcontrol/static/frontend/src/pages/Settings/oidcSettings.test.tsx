import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { AuthConfig, OidcConfig } from '@/api/settings';
import { testOidcConnection } from '@/api/settings';

import { OidcPanel } from './AuthTab';
import {
  isAllowedUrl,
  oidcProblem,
  oidcRedirectUri,
  parseGroupLines,
  removeMapping,
  updateMapping,
} from './oidcSettings';

const client = vi.hoisted(() => ({ apiRequest: vi.fn() }));
const testState = vi.hoisted(() => ({ value: {} as Record<string, unknown> }));

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>();
  return { ...actual, apiRequest: client.apiRequest };
});

vi.mock('@/api/settings', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/settings')>();
  return { ...actual, useTestOidcConnection: () => testState.value };
});

const OIDC: OidcConfig = {
  enabled: true,
  issuer: 'https://idp.example.com/realms/plexus',
  client_id: 'plexus-client',
  client_secret: '••••••••',
  token_auth_method: 'client_secret_basic',
  scopes: 'openid profile email',
  username_claim: 'preferred_username',
  display_name_claim: 'name',
  groups_claim: 'groups',
  admin_groups: ['plexus-admins', 'netops-leads'],
  default_role: 'user',
  default_group_ids: [],
  sync_groups: true,
  group_mappings: [{ group: 'netops', access_group_id: 2 }],
  button_label: 'Sign in with Example ID',
  primary: false,
  redirect_uri: '',
  ca_cert_file: '',
};

const draft = { oidc: OIDC } as unknown as AuthConfig;
const groups = [
  { id: 2, name: 'Network team', description: '', feature_keys: [] },
  { id: 3, name: 'NOC', description: '', feature_keys: [] },
];

describe('oidc settings helpers', () => {
  it('derives the redirect URI unless one is configured', () => {
    expect(oidcRedirectUri('', 'https://plexus.example.com')).toBe(
      'https://plexus.example.com/api/auth/oidc/callback',
    );
    expect(oidcRedirectUri(' https://sso.example.com/cb ', 'x')).toBe('https://sso.example.com/cb');
  });

  it('keeps blank lines while typing admin groups', () => {
    expect(parseGroupLines('a\r\nb\n')).toEqual(['a', 'b', '']);
  });

  it('edits and removes mappings by index', () => {
    const m = [
      { group: 'a', access_group_id: 1 },
      { group: 'b', access_group_id: 2 },
    ];
    expect(updateMapping(m, 1, { access_group_id: 5 })[1]).toEqual({ group: 'b', access_group_id: 5 });
    expect(removeMapping(m, 0)).toEqual([{ group: 'b', access_group_id: 2 }]);
  });

  it('flags what the server would refuse', () => {
    expect(oidcProblem(OIDC)).toBeNull();
    expect(oidcProblem({ ...OIDC, issuer: '' })).toMatch(/issuer/);
    expect(oidcProblem({ ...OIDC, issuer: 'http://idp.example.com' })).toMatch(/https/);
    expect(oidcProblem({ ...OIDC, client_id: ' ' })).toMatch(/client ID/);
    expect(oidcProblem({ ...OIDC, enabled: false, issuer: '' })).toBeNull();
    expect(oidcProblem({ ...OIDC, button_label: 'x'.repeat(61) })).toMatch(/60/);
    expect(
      oidcProblem({ ...OIDC, group_mappings: Array.from({ length: 201 }, () => ({ group: 'g', access_group_id: 1 })) }),
    ).toMatch(/200/);
    expect(isAllowedUrl('http://localhost:8080/realms/lab')).toBe(true);
    expect(isAllowedUrl('not a url')).toBe(false);
  });
});

describe('testOidcConnection', () => {
  beforeEach(() => {
    client.apiRequest.mockReset();
    client.apiRequest.mockResolvedValue({ ok: true });
  });

  it('posts to the admin test route', async () => {
    await testOidcConnection({ issuer: 'https://idp.example.com' });
    expect(client.apiRequest).toHaveBeenCalledWith('/admin/auth-config/oidc/test', {
      method: 'POST',
      body: { issuer: 'https://idp.example.com' },
    });
    await testOidcConnection();
    expect(client.apiRequest).toHaveBeenLastCalledWith('/admin/auth-config/oidc/test', { method: 'POST', body: {} });
  });
});

describe('OidcPanel', () => {
  beforeEach(() => {
    testState.value = { isPending: false, isError: false, data: undefined, mutate: () => {} };
  });

  it('renders the fields, the masked secret and the mappings', () => {
    const html = renderToStaticMarkup(<OidcPanel draft={draft} setDraft={() => {}} groups={groups} />);
    expect(html).toContain('Single sign-on (OpenID Connect)');
    expect(html).toContain('value="https://idp.example.com/realms/plexus"');
    expect(html).toContain('type="password"');
    expect(html).toContain('/api/auth/oidc/callback');
    expect(html).toContain('plexus-admins\nnetops-leads');
    expect(html).toContain('value="netops"');
    expect(html).toContain('Network team');
    expect(html).toContain('Test connection');
  });

  it('says sign-in is off until a redirect URI is saved', () => {
    const notice = 'The redirect URI is not saved yet, so OIDC sign-in is off.';
    const render = (oidc: OidcConfig) =>
      renderToStaticMarkup(
        <OidcPanel draft={{ oidc } as unknown as AuthConfig} setDraft={() => {}} groups={groups} />,
      );
    expect(render(OIDC)).toContain(notice);
    expect(render({ ...OIDC, redirect_uri: 'https://plexus.example.com/api/auth/oidc/callback' })).not.toContain(
      notice,
    );
    expect(render({ ...OIDC, enabled: false })).not.toContain(notice);
  });

  it('shows the test result and the server redirect URI', () => {
    testState.value = {
      isPending: false,
      isError: false,
      mutate: () => {},
      data: {
        ok: true,
        issuer: 'https://idp.example.com/realms/plexus',
        key_count: 2,
        algorithms: ['RS256'],
        redirect_uri: 'https://plexus.example.com/api/auth/oidc/callback',
        error: '',
      },
    };
    const html = renderToStaticMarkup(<OidcPanel draft={draft} setDraft={() => {}} groups={groups} />);
    expect(html).toContain('2 signing key(s)');
    expect(html).toContain('value="https://plexus.example.com/api/auth/oidc/callback"');
    testState.value = { ...testState.value, data: { ok: false, issuer: 'https://idp.example.com', error: 'discovery answered HTTP 404' } };
    expect(renderToStaticMarkup(<OidcPanel draft={draft} setDraft={() => {}} groups={groups} />)).toContain(
      'discovery answered HTTP 404',
    );
  });
});
