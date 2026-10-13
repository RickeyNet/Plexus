import { describe, expect, it } from 'vitest';

import { pathForTab, resolvePathTab, tabFromPath } from './tabPath';

type T = 'one' | 'two' | 'three';
const TABS: readonly T[] = ['one', 'two', 'three'];
const BASE = '/page';

describe('pathForTab', () => {
  it('maps the default tab to the base path and others to a segment', () => {
    expect(pathForTab(BASE, 'one', 'one')).toBe('/page');
    expect(pathForTab(BASE, 'two', 'one')).toBe('/page/two');
  });
});

describe('tabFromPath', () => {
  it('reads the segment after the base', () => {
    expect(tabFromPath('/page/two', BASE, TABS, 'one')).toBe('two');
    expect(tabFromPath('/page/three/extra', BASE, TABS, 'one')).toBe('three');
  });
  it('falls back to the default for the base, unknown segments and other pages', () => {
    expect(tabFromPath('/page', BASE, TABS, 'one')).toBe('one');
    expect(tabFromPath('/page/', BASE, TABS, 'one')).toBe('one');
    expect(tabFromPath('/page/bogus', BASE, TABS, 'one')).toBe('one');
    expect(tabFromPath('/pagetwo', BASE, TABS, 'one')).toBe('one');
    expect(tabFromPath('/other/two', BASE, TABS, 'one')).toBe('one');
  });
});

describe('resolvePathTab', () => {
  const input = { search: '', base: BASE, tabs: TABS, defaultTab: 'one' as T };

  it('needs no redirect for a canonical path', () => {
    expect(resolvePathTab({ ...input, pathname: '/page/two' })).toEqual({ tab: 'two', redirect: null });
    expect(resolvePathTab({ ...input, pathname: '/page' })).toEqual({ tab: 'one', redirect: null });
  });
  it('canonicalises unknown segments and an explicit default segment', () => {
    expect(resolvePathTab({ ...input, pathname: '/page/bogus' })).toEqual({
      tab: 'one',
      redirect: { pathname: '/page', search: '' },
    });
    expect(resolvePathTab({ ...input, pathname: '/page/one' }).redirect?.pathname).toBe('/page');
  });
  it('moves a legacy ?tab= query into the path and keeps other params', () => {
    expect(resolvePathTab({ ...input, pathname: '/page', search: '?tab=three&x=1' })).toEqual({
      tab: 'three',
      redirect: { pathname: '/page/three', search: '?x=1' },
    });
  });
  it('drops an unknown legacy ?tab= value', () => {
    expect(resolvePathTab({ ...input, pathname: '/page/two', search: '?tab=nope' })).toEqual({
      tab: 'two',
      redirect: { pathname: '/page/two', search: '' },
    });
  });
  it('sends a tab the user may not open to the first allowed tab', () => {
    expect(resolvePathTab({ ...input, pathname: '/page', allowed: ['two', 'three'] })).toEqual({
      tab: 'two',
      redirect: { pathname: '/page/two', search: '' },
    });
  });
  it('keeps the requested tab when nothing is allowed', () => {
    expect(resolvePathTab({ ...input, pathname: '/page/three', allowed: [] })).toEqual({
      tab: 'three',
      redirect: null,
    });
  });
});
