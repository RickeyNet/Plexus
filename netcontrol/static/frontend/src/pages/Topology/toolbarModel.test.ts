import { describe, expect, it } from 'vitest';

import { LAYOUT_OPTIONS, badgeText, enabledOverlayCount, layoutLabel } from './toolbarModel';

describe('enabledOverlayCount', () => {
  it('counts the overlays that are on', () => {
    expect(enabledOverlayCount({ util: false, stp: false, status: false })).toBe(0);
    expect(enabledOverlayCount({ util: true, stp: false, status: true })).toBe(2);
  });
});

describe('badgeText', () => {
  it('hides zero and caps at 99+', () => {
    expect(badgeText(0)).toBeNull();
    expect(badgeText(-1)).toBeNull();
    expect(badgeText(7)).toBe('7');
    expect(badgeText(100)).toBe('99+');
  });
});

describe('layoutLabel', () => {
  it('names every layout', () => {
    expect(new Set(LAYOUT_OPTIONS.map((o) => o.value)).size).toBe(LAYOUT_OPTIONS.length);
    expect(layoutLabel('circular')).toBe('Circular');
  });
});
