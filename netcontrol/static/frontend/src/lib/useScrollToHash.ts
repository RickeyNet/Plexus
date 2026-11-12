import { useEffect } from 'react';
import { useLocation } from 'react-router';

/**
 * Scrolls the element whose id is the URL's `#anchor` into view whenever a
 * navigation lands on one (the router does not, unlike a full page load).
 * A link followed again scrolls again: each navigation has its own key.
 * Pass `ready` false while the page has not rendered its anchors yet.
 */
export function useScrollToHash(ready = true, behavior: ScrollBehavior = 'auto') {
  const { hash, key } = useLocation();
  useEffect(() => {
    if (!ready || hash.length < 2) return;
    document.getElementById(hash.slice(1))?.scrollIntoView?.({ behavior, block: 'start' });
  }, [hash, key, ready, behavior]);
}
