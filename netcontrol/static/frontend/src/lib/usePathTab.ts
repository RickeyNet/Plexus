import { useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router';

import { pathForTab, resolvePathTab } from './tabPath';

/**
 * Tab state for a page whose tab lives in the URL path (`/page`,
 * `/page/<tab>`). Returns the tab to render and a selector that navigates to
 * the tab's path. Unknown segments, legacy `?tab=` links and tabs the user
 * may not open are rewritten in place (`replace`) so the URL always names the
 * rendered tab. Pass `allowed` only once auth has loaded. Name tabs with
 * their own nested tab segments (`/page/<tab>/<sub>`) in `nested` so those
 * segments survive; the nested component resolves them with its own
 * `usePathTab`.
 */
export function usePathTab<K extends string>(
  base: string,
  tabs: readonly K[],
  defaultTab: K,
  allowed?: readonly K[],
  nested?: readonly K[],
): [K, (tab: K) => void] {
  const { pathname, search, hash } = useLocation();
  const navigate = useNavigate();
  const { tab, redirect } = resolvePathTab({ pathname, search, base, tabs, defaultTab, allowed, nested });

  const redirectPath = redirect?.pathname;
  const redirectSearch = redirect?.search;
  useEffect(() => {
    if (redirectPath === undefined) return;
    navigate({ pathname: redirectPath, search: redirectSearch, hash }, { replace: true });
  }, [redirectPath, redirectSearch, hash, navigate]);

  function selectTab(next: K) {
    if (next === tab) return; // re-clicking the open tab keeps its nested segments
    const target = pathForTab(base, next, defaultTab);
    if (target !== pathname) navigate(target);
  }

  return [tab, selectTab];
}
