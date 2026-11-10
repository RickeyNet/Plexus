import type { KeyboardEvent } from 'react';

export interface ClickableProps {
  role?: 'button';
  tabIndex: 0;
  onClick: () => void;
  onKeyDown: (e: KeyboardEvent<HTMLElement>) => void;
}

/** True for the keys that activate a button: Enter and Space. */
export function isActivationKey(key: string): boolean {
  return key === 'Enter' || key === ' ';
}

/**
 * Props that make a non-button element (a card, a header strip, a table row)
 * work from the keyboard the way it works with the mouse: focusable, and
 * activated by Enter or Space. Spread onto the element next to its own props.
 *
 * Pass `role: null` for a `<tr>`, which must keep its row role for the table
 * to read correctly. A key pressed on a control inside the element (a button,
 * a checkbox) is left to that control.
 */
export function clickableProps(
  onActivate: () => void,
  { role = 'button' }: { role?: 'button' | null } = {},
): ClickableProps {
  return {
    ...(role ? { role } : {}),
    tabIndex: 0,
    onClick: onActivate,
    onKeyDown: (e) => {
      if (e.target !== e.currentTarget || !isActivationKey(e.key)) return;
      e.preventDefault();
      onActivate();
    },
  };
}
