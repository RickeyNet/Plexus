import { type CSSProperties, useCallback, useState } from 'react';

import { safeGet, safeSet } from './appearance';

/**
 * Whether a list page's side panel (a record's detail, the subnet drilldown)
 * is widened to the page's full width. One choice for every such page, kept
 * in this browser.
 */
export const WIDE_DETAIL_KEY = 'plexus.wideDetail';

export function useWideDetail(): [boolean, () => void] {
  const [wide, setWide] = useState(() => safeGet(WIDE_DETAIL_KEY) === '1');
  const toggle = useCallback(() => {
    setWide((w) => {
      safeSet(WIDE_DETAIL_KEY, w ? '0' : '1');
      return !w;
    });
  }, []);
  return [wide, toggle];
}

/** The list and side panel side by side, or one above the other when widened. */
export function splitGridStyle(wide: boolean): CSSProperties {
  return {
    display: 'grid',
    gridTemplateColumns: wide ? 'minmax(0, 1fr)' : 'minmax(0, 2.1fr) minmax(320px, 1fr)',
    gap: '1rem',
    alignItems: 'start',
  };
}

/**
 * A detail panel's stack of sections. The one column is `minmax(0, 1fr)` so
 * a wide table scrolls inside the card instead of stretching its section past
 * the card's edge (a grid item is otherwise as wide as its content).
 */
export const DETAIL_STACK_STYLE: CSSProperties = { display: 'grid', gridTemplateColumns: 'minmax(0, 1fr)', gap: '1rem' };

/** Scroll a panel back into view unless its top is already in the upper half of the screen. */
export function bringIntoView(el: HTMLElement | null) {
  if (!el) return;
  const top = el.getBoundingClientRect().top;
  if (top < 0 || top > window.innerHeight / 2) el.scrollIntoView?.({ block: 'start' });
}
