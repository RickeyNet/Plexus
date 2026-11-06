import type { AuthStatus } from '@/api/auth';
import { isNavItemVisible, type NavGate, type NavVisibilityContext } from '@/components/navVisibility';

/** A page tab that may be gated on a feature, using the same rules as the sidebar. */
export interface GatedTab<K extends string = string> extends NavGate {
  key: K;
}

/**
 * The tabs this user may open: not hidden globally by an admin, and either
 * ungated, or the user is an admin, or the user has one of the tab's features.
 * Same rules as `isNavItemVisible` so a tab never shows when its sidebar entry
 * would not.
 */
export function visibleTabs<T extends GatedTab>(tabs: readonly T[], auth: AuthStatus | undefined): T[] {
  const ctx = visibilityContext(auth);
  return tabs.filter((t) => isNavItemVisible(t, ctx));
}

/**
 * Whether this user may open the pages of `feature` (same rules as a tab or
 * sidebar entry gated on it). Use it to enable a query against an API the
 * feature gates, so users without it never request it.
 */
export function canUseFeature(feature: string, auth: AuthStatus | undefined): boolean {
  return isNavItemVisible({ feature }, visibilityContext(auth));
}

function visibilityContext(auth: AuthStatus | undefined): NavVisibilityContext {
  return {
    isAdmin: auth?.role === 'admin',
    access: new Set(auth?.feature_access ?? []),
    hidden: new Set(auth?.feature_visibility_hidden ?? []),
  };
}

/**
 * The tab to render: `requested` when the user may open it, otherwise the
 * first visible tab. With no visible tab at all, `requested` is kept so the
 * page still renders something (its API will refuse the data).
 */
export function resolveTab<K extends string>(requested: K, visible: readonly GatedTab<K>[]): K {
  if (visible.some((t) => t.key === requested)) return requested;
  return visible[0]?.key ?? requested;
}
