import { describe, expect, it } from 'vitest';

import { CONFIGURE_FEATURES, CONFIGURE_TABS } from '@/pages/Monitoring/configureTabs';

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

  it('shows Configuration to users with only config-backups', () => {
    // The Configuration page has a drift tab and backup tabs on different
    // features; a user with either must still reach the page.
    const item = { feature: ['config-drift', 'config-backups'], visKey: 'configuration' };
    expect(isNavItemVisible(item, ctx({ access: ['config-backups'] }))).toBe(true);
    expect(isNavItemVisible(item, ctx({ access: ['config-drift'] }))).toBe(true);
    expect(isNavItemVisible(item, ctx({ access: ['inventory'] }))).toBe(false);
    expect(isNavItemVisible(item, ctx({ access: ['config-backups'], hidden: ['configuration'] }))).toBe(false);
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

  it('shows Network Tools when the user has either tool', () => {
    const item = { feature: ['mac-tracking', 'traffic-analysis'] };
    expect(isNavItemVisible(item, ctx({ access: ['mac-tracking'] }))).toBe(true);
    expect(isNavItemVisible(item, ctx({ access: ['traffic-analysis'] }))).toBe(true);
    expect(isNavItemVisible(item, ctx({ access: ['ipam'] }))).toBe(false);
    const access = ['mac-tracking', 'traffic-analysis'];
    expect(isNavItemVisible(item, ctx({ access, hidden: ['mac-tracking'] }))).toBe(true);
    expect(isNavItemVisible(item, ctx({ access, hidden: ['mac-tracking', 'traffic-analysis'] }))).toBe(false);
  });
});

describe('Monitoring Configure tab gate', () => {
  const configure = { feature: CONFIGURE_FEATURES };
  const shownSubTabs = (c: NavVisibilityContext) => CONFIGURE_TABS.filter((t) => isNavItemVisible(t, c)).map((t) => t.key);

  it('gates on every feature its sub-tabs need', () => {
    expect([...CONFIGURE_FEATURES].sort()).toEqual(['graph-templates', 'monitoring']);
  });

  it('shows Configure with only the graph sub-tabs to a graph-templates-only user', () => {
    const c = ctx({ access: ['graph-templates'] });
    expect(isNavItemVisible(configure, c)).toBe(true);
    expect(shownSubTabs(c)).toEqual(['graph-templates', 'host-templates', 'graph-trees']);
  });

  it('shows Configure with only the monitoring sub-tabs to a monitoring-only user', () => {
    const c = ctx({ access: ['monitoring'] });
    expect(isNavItemVisible(configure, c)).toBe(true);
    expect(shownSubTabs(c)).toEqual(['rules', 'suppressions', 'sla-targets', 'oid-profiles']);
  });

  it('hides Configure when neither feature is available', () => {
    expect(isNavItemVisible(configure, ctx({ access: ['ipam'] }))).toBe(false);
    const access = ['monitoring', 'graph-templates'];
    expect(isNavItemVisible(configure, ctx({ access, hidden: ['graph-templates'] }))).toBe(true);
    expect(isNavItemVisible(configure, ctx({ access, hidden: ['monitoring', 'graph-templates'] }))).toBe(false);
  });
});
