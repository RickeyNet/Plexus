// Keyboard navigation for <Menu>, kept apart from Menu.tsx so it can be unit
// tested (component files may only export components).

/**
 * The index of the item to focus after `key` is pressed, or null when the key
 * does not move focus. `current` is -1 when no item has focus yet. Arrow keys
 * wrap around; Home/End jump to the ends.
 */
export function nextMenuIndex(current: number, count: number, key: string): number | null {
  if (count <= 0) return null;
  switch (key) {
    case 'ArrowDown':
      return current < 0 ? 0 : (current + 1) % count;
    case 'ArrowUp':
      return current < 0 ? count - 1 : (current - 1 + count) % count;
    case 'Home':
      return 0;
    case 'End':
      return count - 1;
    default:
      return null;
  }
}

export interface MenuPosition {
  top: number;
  left?: number;
  right?: number;
}

/**
 * Fixed-position coordinates that put the menu just below its trigger, its
 * left edge on the trigger's left (`start`) or its right edge on the trigger's
 * right (`end`).
 */
export function menuPosition(
  trigger: { bottom: number; left: number; right: number },
  align: 'start' | 'end',
  viewportWidth: number,
  gap = 4,
): MenuPosition {
  const top = trigger.bottom + gap;
  return align === 'end' ? { top, right: Math.max(0, viewportWidth - trigger.right) } : { top, left: Math.max(0, trigger.left) };
}
