import { describe, expect, it } from 'vitest';

import type { AuthStatus } from '@/api/auth';
import { canUseFeature, canWriteFeature, resolveTab, visibleTabs, type GatedTab } from './tabGating';

const TABS: GatedTab<'a' | 'b' | 'c'>[] = [
  { key: 'a', feature: 'alpha' },
  { key: 'b', feature: 'beta' },
  { key: 'c' },
];

function auth(over: Partial<AuthStatus>): AuthStatus {
  return { authenticated: true, role: 'user', feature_access: [], feature_visibility_hidden: [], ...over } as AuthStatus;
}

describe('visibleTabs', () => {
  it('shows only tabs whose feature the user has, plus ungated tabs', () => {
    const v = visibleTabs(TABS, auth({ feature_access: ['beta'] })).map((t) => t.key);
    expect(v).toEqual(['b', 'c']);
  });
  it('admins see every tab except globally hidden ones', () => {
    const v = visibleTabs(TABS, auth({ role: 'admin', feature_visibility_hidden: ['alpha'] })).map((t) => t.key);
    expect(v).toEqual(['b', 'c']);
  });
  it('a hidden feature hides the tab even when the user has access', () => {
    const v = visibleTabs(TABS, auth({ feature_access: ['alpha', 'beta'], feature_visibility_hidden: ['beta'] })).map((t) => t.key);
    expect(v).toEqual(['a', 'c']);
  });
  it('with no auth yet, only ungated tabs show', () => {
    expect(visibleTabs(TABS, undefined).map((t) => t.key)).toEqual(['c']);
  });
});

describe('resolveTab', () => {
  it('keeps the requested tab when visible', () => {
    expect(resolveTab('b', TABS)).toBe('b');
  });
  it('falls back to the first visible tab', () => {
    expect(resolveTab('a', TABS.slice(1))).toBe('b');
  });
  it('keeps the request when nothing is visible', () => {
    expect(resolveTab('a', [])).toBe('a');
  });
});

describe('canUseFeature', () => {
  it('follows the tab rules for one feature', () => {
    expect(canUseFeature('topology', auth({ feature_access: ['topology'] }))).toBe(true);
    expect(canUseFeature('topology', auth({ feature_access: ['dashboard'] }))).toBe(false);
    expect(canUseFeature('topology', auth({ role: 'admin' }))).toBe(true);
    expect(canUseFeature('topology', auth({ role: 'admin', feature_visibility_hidden: ['topology'] }))).toBe(false);
    expect(canUseFeature('topology', undefined)).toBe(false);
  });
});

describe('canWriteFeature', () => {
  it('needs the write key, and no read-only object scope', () => {
    expect(canWriteFeature('ipam', auth({ feature_access: ['ipam', 'ipam.write'] }))).toBe(true);
    expect(canWriteFeature('ipam', auth({ feature_access: ['ipam'] }))).toBe(false);
    const readOnly = { restricted: true, write_group_ids: [], read_only: true };
    expect(canWriteFeature('ipam', auth({ feature_access: ['ipam', 'ipam.write'], object_scope: readOnly }))).toBe(false);
    const writable = { restricted: true, write_group_ids: [3], read_only: false };
    expect(canWriteFeature('ipam', auth({ feature_access: ['ipam', 'ipam.write'], object_scope: writable }))).toBe(true);
    expect(canWriteFeature('ipam', auth({ role: 'admin' }))).toBe(true);
    expect(canWriteFeature('ipam', undefined)).toBe(false);
  });
});
