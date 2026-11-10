// Collapsed/expanded state of the desktop sidebar.
//
// Three viewport bands:
//   mobile (<= 768px)  - the sidebar is an off-canvas drawer, never collapsed.
//   narrow (<= 1024px) - collapsed by default to give the page the room; the
//                        toggle overrides that until the viewport leaves the band.
//   wide               - follows the user's saved preference (expanded if none).

export const SIDEBAR_COLLAPSED_KEY = 'plexus-sidebar-collapsed';
export const SIDEBAR_MOBILE_QUERY = '(max-width: 768px)';
export const SIDEBAR_NARROW_QUERY = '(max-width: 1024px)';

export function parseCollapsedPref(raw: string | null): boolean | null {
  if (raw === '1') return true;
  if (raw === '0') return false;
  return null;
}

export function serializeCollapsedPref(collapsed: boolean): string {
  return collapsed ? '1' : '0';
}

export interface SidebarViewState {
  mobile: boolean;
  narrow: boolean;
  /** Saved wide-screen preference; null when the user never toggled. */
  pref: boolean | null;
  /** Toggle made while in the narrow band; null when untouched. */
  narrowOverride: boolean | null;
}

export function resolveCollapsed({ mobile, narrow, pref, narrowOverride }: SidebarViewState): boolean {
  if (mobile) return false;
  if (narrow) return narrowOverride ?? true;
  return pref ?? false;
}
