import { describe, expect, it } from 'vitest';

import { menuPosition, nextMenuIndex } from './menuNav';

describe('nextMenuIndex', () => {
  it('moves down and wraps to the first item', () => {
    expect(nextMenuIndex(0, 3, 'ArrowDown')).toBe(1);
    expect(nextMenuIndex(2, 3, 'ArrowDown')).toBe(0);
  });

  it('moves up and wraps to the last item', () => {
    expect(nextMenuIndex(1, 3, 'ArrowUp')).toBe(0);
    expect(nextMenuIndex(0, 3, 'ArrowUp')).toBe(2);
  });

  it('starts at an end when nothing has focus', () => {
    expect(nextMenuIndex(-1, 3, 'ArrowDown')).toBe(0);
    expect(nextMenuIndex(-1, 3, 'ArrowUp')).toBe(2);
  });

  it('jumps with Home and End', () => {
    expect(nextMenuIndex(1, 4, 'Home')).toBe(0);
    expect(nextMenuIndex(1, 4, 'End')).toBe(3);
  });

  it('ignores other keys and empty menus', () => {
    expect(nextMenuIndex(0, 3, 'a')).toBeNull();
    expect(nextMenuIndex(-1, 0, 'ArrowDown')).toBeNull();
  });
});

describe('menuPosition', () => {
  const trigger = { bottom: 100, left: 40, right: 140 };

  it('aligns the right edges for end', () => {
    expect(menuPosition(trigger, 'end', 1000)).toEqual({ top: 104, right: 860 });
  });

  it('aligns the left edges for start', () => {
    expect(menuPosition(trigger, 'start', 1000)).toEqual({ top: 104, left: 40 });
  });
});
