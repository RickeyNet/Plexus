import { describe, expect, it } from 'vitest';

import type { AuthStatus } from '@/api/auth';

import { addSourceAccess, canAddSource } from './addSource';

const auth = (over: Partial<AuthStatus>): AuthStatus => ({ authenticated: true, ...over });

describe('addSourceAccess', () => {
  it('offers both kinds to an admin', () => {
    const access = addSourceAccess(auth({ role: 'admin' }));
    expect(access).toEqual({ org: true, cloud: true });
    expect(canAddSource(access)).toBe(true);
  });

  it('offers nothing to a user who is not an admin, whatever features they have', () => {
    const access = addSourceAccess(auth({ role: 'user', feature_access: ['topology', 'cloud-visibility'] }));
    expect(access).toEqual({ org: false, cloud: false });
    expect(canAddSource(access)).toBe(false);
  });

  it('leaves out the sources of a feature hidden globally', () => {
    expect(addSourceAccess(auth({ role: 'admin', feature_visibility_hidden: ['cloud-visibility'] }))).toEqual({
      org: true,
      cloud: false,
    });
    expect(addSourceAccess(auth({ role: 'admin', feature_visibility_hidden: ['topology'] }))).toEqual({
      org: false,
      cloud: true,
    });
  });

  it('offers nothing before the session is known or when logged out', () => {
    expect(canAddSource(addSourceAccess(undefined))).toBe(false);
    expect(canAddSource(addSourceAccess({ authenticated: false, role: 'admin' }))).toBe(false);
  });
});
