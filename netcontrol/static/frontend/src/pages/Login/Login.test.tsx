import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router';
import { describe, expect, it, vi } from 'vitest';

import { SSO_ERROR_MESSAGES, enabledSsoMethods, ssoErrorMessage, ssoLoginHref, type SsoStatus } from '@/api/auth';

import { Login } from './Login';

const mutation = { isPending: false, mutateAsync: async () => ({}) };

vi.mock('@/api/auth', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/auth')>();
  return { ...actual, useLogin: () => mutation, useRegister: () => mutation };
});

function render(path: string, sso?: SsoStatus) {
  return renderToStaticMarkup(
    <MemoryRouter initialEntries={[path]}>
      <Login sso={sso} />
    </MemoryRouter>,
  );
}

const enabled = (primary = false): SsoStatus => ({
  oidc: { enabled: true, label: 'Sign in with Example ID', primary },
});

describe('ssoErrorMessage', () => {
  it('maps every code to a fixed sentence and unknown codes to the provider one', () => {
    expect(ssoErrorMessage('')).toBeNull();
    expect(ssoErrorMessage('?x=1')).toBeNull();
    for (const code of ['disabled', 'state', 'provider', 'token', 'claims', 'account', 'denied']) {
      expect(ssoErrorMessage(`?sso_error=${code}`)).toBe(SSO_ERROR_MESSAGES[code]);
    }
    expect(ssoErrorMessage('?sso_error=<script>')).toBe(SSO_ERROR_MESSAGES.provider);
  });
});

describe('ssoLoginHref', () => {
  it('carries the current page as next, without sso_error', () => {
    expect(ssoLoginHref('/devices/7', '?tab=config&sso_error=state')).toBe(
      '/api/auth/oidc/login?next=%2Fdevices%2F7%3Ftab%3Dconfig',
    );
    expect(ssoLoginHref('/', '')).toBe('/api/auth/oidc/login');
    expect(ssoLoginHref('/login', '?sso_error=token')).toBe('/api/auth/oidc/login');
  });
});

describe('Login', () => {
  it('shows no SSO button when single sign-on is off', () => {
    const html = render('/', { oidc: { enabled: false, label: 'Sign in with SSO', primary: false } });
    expect(html).not.toContain('/api/auth/oidc/login');
    expect(html).toContain('Sign In');
  });

  it('offers the SSO button under the password form', () => {
    const html = render('/devices/7', enabled());
    expect(html).toContain('Sign in with Example ID');
    expect(html).toContain('href="/api/auth/oidc/login?next=%2Fdevices%2F7"');
    expect(html).toContain('login-password');
  });

  it('leads with SSO when primary and folds the password form away', () => {
    const html = render('/', enabled(true));
    expect(html).toContain('Sign in with Example ID');
    expect(html).toContain('Use a local account');
    expect(html).not.toContain('login-password');
  });

  it('shows the fixed sentence for an sso_error code, never the raw value', () => {
    const html = render('/login?sso_error=account', enabled());
    expect(html).toContain('Your account could not be signed in through single sign-on.');
    expect(html).not.toContain('sso_error=account');
    const primary = render('/login?sso_error=state', enabled(true));
    expect(primary).toContain('The sign-in request expired or did not match.');
  });
});

describe('Login with SAML', () => {
  const both = (samlPrimary = false): SsoStatus => ({
    oidc: { enabled: true, label: 'Sign in with Example ID', primary: false },
    saml: { enabled: true, label: 'Sign in with Example SAML', primary: samlPrimary },
  });

  it('builds the SAML login href', () => {
    expect(ssoLoginHref('/devices/7', '', 'saml')).toBe('/api/auth/saml/login?next=%2Fdevices%2F7');
    expect(ssoLoginHref('/', '', 'saml')).toBe('/api/auth/saml/login');
  });

  it('lists enabled methods, OIDC first', () => {
    expect(enabledSsoMethods(undefined)).toEqual([]);
    expect(enabledSsoMethods(both()).map((m) => m.protocol)).toEqual(['oidc', 'saml']);
    expect(
      enabledSsoMethods({ saml: { enabled: false, label: 'x', primary: true } }).map((m) => m.protocol),
    ).toEqual([]);
  });

  it('offers both buttons under the password form', () => {
    const html = render('/devices/7', both());
    expect(html).toContain('href="/api/auth/oidc/login?next=%2Fdevices%2F7"');
    expect(html).toContain('href="/api/auth/saml/login?next=%2Fdevices%2F7"');
    expect(html).toContain('Sign in with Example SAML');
    expect(html).toContain('login-password');
  });

  it('leads with SSO when SAML alone is primary', () => {
    const html = render('/', { saml: { enabled: true, label: 'Sign in with Example SAML', primary: true } });
    expect(html).toContain('href="/api/auth/saml/login"');
    expect(html).toContain('Use a local account');
    expect(html).not.toContain('login-password');
  });
});
