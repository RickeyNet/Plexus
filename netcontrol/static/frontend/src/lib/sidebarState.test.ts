import { describe, expect, it } from 'vitest';

import { parseCollapsedPref, resolveCollapsed, serializeCollapsedPref } from './sidebarState';

const wide = { mobile: false, narrow: false, pref: null, narrowOverride: null };

describe('parseCollapsedPref', () => {
  it('round-trips a saved preference', () => {
    expect(parseCollapsedPref(serializeCollapsedPref(true))).toBe(true);
    expect(parseCollapsedPref(serializeCollapsedPref(false))).toBe(false);
  });

  it('treats missing or unknown values as no preference', () => {
    expect(parseCollapsedPref(null)).toBeNull();
    expect(parseCollapsedPref('yes')).toBeNull();
  });
});

describe('resolveCollapsed', () => {
  it('is expanded on a wide screen with no preference', () => {
    expect(resolveCollapsed(wide)).toBe(false);
  });

  it('follows the saved preference on a wide screen', () => {
    expect(resolveCollapsed({ ...wide, pref: true })).toBe(true);
    expect(resolveCollapsed({ ...wide, pref: false })).toBe(false);
  });

  it('collapses by default in the narrow band, whatever the wide preference', () => {
    expect(resolveCollapsed({ ...wide, narrow: true })).toBe(true);
    expect(resolveCollapsed({ ...wide, narrow: true, pref: false })).toBe(true);
  });

  it('lets the toggle override the narrow default', () => {
    expect(resolveCollapsed({ ...wide, narrow: true, narrowOverride: false })).toBe(false);
  });

  it('is never collapsed on mobile, where the sidebar is a drawer', () => {
    expect(resolveCollapsed({ mobile: true, narrow: true, pref: true, narrowOverride: true })).toBe(false);
  });
});
