import { describe, expect, it } from 'vitest';

import { isBackdropDismiss, trapTabTarget } from './modalFocus';

describe('trapTabTarget', () => {
  it('keeps focus on the dialog when nothing is focusable', () => {
    expect(trapTabTarget(-1, 0, false)).toBe('self');
    expect(trapTabTarget(-1, 0, true)).toBe('self');
  });

  it('enters at the first or last element when focus is not on one', () => {
    expect(trapTabTarget(-1, 3, false)).toBe(0);
    expect(trapTabTarget(-1, 3, true)).toBe(2);
  });

  it('wraps from the last element to the first on Tab', () => {
    expect(trapTabTarget(2, 3, false)).toBe(0);
  });

  it('wraps from the first element to the last on Shift+Tab', () => {
    expect(trapTabTarget(0, 3, true)).toBe(2);
  });

  it('leaves Tab alone in the middle of the dialog', () => {
    expect(trapTabTarget(1, 3, false)).toBeNull();
    expect(trapTabTarget(1, 3, true)).toBeNull();
    expect(trapTabTarget(0, 3, false)).toBeNull();
    expect(trapTabTarget(2, 3, true)).toBeNull();
  });

  it('wraps onto itself when there is a single element', () => {
    expect(trapTabTarget(0, 1, false)).toBe(0);
    expect(trapTabTarget(0, 1, true)).toBe(0);
  });
});

describe('isBackdropDismiss', () => {
  it('closes only when press and release are both on the backdrop', () => {
    expect(isBackdropDismiss(true, true)).toBe(true);
  });

  it('ignores a drag that starts inside the dialog', () => {
    expect(isBackdropDismiss(false, true)).toBe(false);
  });

  it('ignores a drag that ends inside the dialog', () => {
    expect(isBackdropDismiss(true, false)).toBe(false);
  });
});
