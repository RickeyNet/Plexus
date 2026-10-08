import { describe, expect, it } from 'vitest';

import { isNavItemVisible, type NavVisibilityContext } from './navVisibility';

function ctx(opts: { isAdmin?: boolean; access?: string[]; hidden?: string[] } = {}): NavVisibilityContext {
  return {
    isAdmin: opts.isAdmin ?? false,
    access: new Set(opts.access ?? []),
    hidden: new Set(opts.hidden ?? []),
  };
}

describe('isNavItemVisible', () => {
  it('shows a string feature to users who have it', () => {
    expect(isNavItemVisible({ feature: 'ipam' }, ctx({ access: ['ipam'] }))).toBe(true);
  });

  it('hides a string feature from users who lack it', () => {
    expect(isNavItemVisible({ feature: 'ipam' }, ctx({ access: ['topology'] }))).toBe(false);
  });

  it('hides a string feature hidden globally', () => {
    expect(isNavItemVisible({ feature: 'ipam' }, ctx({ access: ['ipam'], hidden: ['ipam'] }))).toBe(false);
  });

  it('shows an array feature when the user has any of its features', () => {
    const item = { feature: ['software', 'upgrades'] };
    expect(isNavItemVisible(item, ctx({ access: ['upgrades'] }))).toBe(true);
    expect(isNavItemVisible(item, ctx({ access: ['software'] }))).toBe(true);
    expect(isNavItemVisible(item, ctx({ access: ['ipam'] }))).toBe(false);
  });

  it('hides an array feature only when all of its features are hidden', () => {
    const item = { feature: ['software', 'upgrades'] };
    const access = ['software', 'upgrades'];
    expect(isNavItemVisible(item, ctx({ access, hidden: ['software'] }))).toBe(true);
    expect(isNavItemVisible(item, ctx({ access, hidden: ['upgrades'] }))).toBe(true);
    expect(isNavItemVisible(item, ctx({ access, hidden: ['software', 'upgrades'] }))).toBe(false);
  });

  it('hides an item whose explicit visKey is hidden', () => {
    const item = { feature: 'config-drift', visKey: 'configuration' };
    expect(isNavItemVisible(item, ctx({ access: ['config-drift'], hidden: ['configuration'] }))).toBe(false);
    expect(isNavItemVisible(item, ctx({ access: ['config-drift'], hidden: ['config-drift'] }))).toBe(true);
  });

  it('uses an explicit visKey instead of the array rule', () => {
    const item = { feature: ['a', 'b'], visKey: 'group' };
    expect(isNavItemVisible(item, ctx({ access: ['a'], hidden: ['a', 'b'] }))).toBe(true);
    expect(isNavItemVisible(item, ctx({ access: ['a'], hidden: ['group'] }))).toBe(false);
  });

  it('shows the alternative feature to users who have it', () => {
    const item = { feature: 'risk-analysis', altFeature: 'deployments' };
    expect(isNavItemVisible(item, ctx({ access: ['deployments'] }))).toBe(true);
  });

  it('always shows an item without a feature', () => {
    expect(isNavItemVisible({}, ctx())).toBe(true);
    expect(isNavItemVisible({}, ctx({ hidden: ['settings'] }))).toBe(true);
  });

  it('lets admins bypass access but not global hiding', () => {
    expect(isNavItemVisible({ feature: 'ipam' }, ctx({ isAdmin: true }))).toBe(true);
    expect(isNavItemVisible({ feature: ['software', 'upgrades'] }, ctx({ isAdmin: true }))).toBe(true);
    expect(isNavItemVisible({ feature: 'ipam' }, ctx({ isAdmin: true, hidden: ['ipam'] }))).toBe(false);
    expect(
      isNavItemVisible({ feature: ['software', 'upgrades'] }, ctx({ isAdmin: true, hidden: ['software', 'upgrades'] })),
    ).toBe(false);
  });
});
