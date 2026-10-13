// Pure path <-> tab mapping for pages whose tab lives in the URL path:
// `/page` is the default tab and `/page/<tab>` the others. `usePathTab` wraps
// these for components; they live apart so they can be unit tested.

/** The URL path that shows `tab` on the page mounted at `base`. */
export function pathForTab<K extends string>(base: string, tab: K, defaultTab: K): string {
  return tab === defaultTab ? base : `${base}/${tab}`;
}

/** The tab named by `pathname` under `base`; an unknown or missing segment is the default tab. */
export function tabFromPath<K extends string>(
  pathname: string,
  base: string,
  tabs: readonly K[],
  defaultTab: K,
): K {
  if (pathname !== base && !pathname.startsWith(`${base}/`)) return defaultTab;
  const segment = pathname.slice(base.length + 1).split('/')[0];
  return (tabs as readonly string[]).includes(segment) ? (segment as K) : defaultTab;
}

export interface PathTabInput<K extends string> {
  pathname: string;
  search: string;
  base: string;
  tabs: readonly K[];
  defaultTab: K;
  /** Tabs this user may open, in display order. Omit to allow every tab. */
  allowed?: readonly K[];
}

export interface PathTabResult<K extends string> {
  /** The tab to render. */
  tab: K;
  /** Where the URL should be, or null when it already names `tab` canonically. */
  redirect: { pathname: string; search: string } | null;
}

/**
 * Resolve the tab to render and whether the URL needs correcting. A legacy
 * `?tab=<key>` query (the pre-path convention) wins over the path and is
 * dropped from the URL. A tab the user may not open falls back to the first
 * allowed one; with none allowed the requested tab is kept (its API refuses
 * the data). The redirect makes the URL name the rendered tab canonically.
 */
export function resolvePathTab<K extends string>({
  pathname,
  search,
  base,
  tabs,
  defaultTab,
  allowed,
}: PathTabInput<K>): PathTabResult<K> {
  const params = new URLSearchParams(search);
  const legacy = params.get('tab');
  const hasLegacy = params.has('tab');
  params.delete('tab');

  const requested =
    legacy !== null && (tabs as readonly string[]).includes(legacy)
      ? (legacy as K)
      : tabFromPath(pathname, base, tabs, defaultTab);
  const tab = !allowed || allowed.includes(requested) ? requested : (allowed[0] ?? requested);

  const canonical = pathForTab(base, tab, defaultTab);
  if (canonical === pathname && !hasLegacy) return { tab, redirect: null };
  const rest = params.toString();
  return { tab, redirect: { pathname: canonical, search: rest ? `?${rest}` : '' } };
}
