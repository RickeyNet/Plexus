// Sidebar visibility rules, kept apart from Sidebar.tsx so they can be unit
// tested (Sidebar.tsx may only export components).

/** The gating fields of a sidebar entry. */
export interface NavGate {
  // Per-user gateable feature key (FEATURE_FLAGS). Omit for items always
  // visible to authenticated users (e.g., Settings). May be an array, in
  // which case the entry is visible if the user has *any* listed feature
  // (e.g., Delegator gates on four sub-features at once).
  feature?: string | string[];
  // Optional second feature flag - entry is visible if user has either.
  // Used for grouped pages like Changes (risk-analysis | deployments).
  altFeature?: string;
  // Global visibility key (FEATURE_VISIBILITY_CATALOG) - what admins can hide
  // via Settings → Features. Defaults to `feature` if not set.
  visKey?: string;
}

export interface NavVisibilityContext {
  isAdmin: boolean;
  access: Set<string>;
  hidden: Set<string>;
}

/** Whether an admin hid the entry globally under Settings → Features. */
function isHiddenGlobally(item: NavGate, hidden: Set<string>): boolean {
  if (item.visKey !== undefined) return Boolean(item.visKey) && hidden.has(item.visKey);
  // An entry gating on several features (Delegator, Software) stands for
  // several pages or tabs, so it disappears only once every one of them is
  // hidden; hiding one of them leaves the entry for the others.
  if (Array.isArray(item.feature)) return item.feature.length > 0 && item.feature.every((f) => hidden.has(f));
  return Boolean(item.feature) && hidden.has(item.feature as string);
}

/**
 * Whether a sidebar entry is shown: not hidden globally, and either ungated,
 * or the user is an admin, or the user has one of its features. Admins see
 * every entry except the ones hidden globally.
 */
export function isNavItemVisible(item: NavGate, { isAdmin, access, hidden }: NavVisibilityContext): boolean {
  if (isHiddenGlobally(item, hidden)) return false;
  if (!item.feature) return true; // always-visible (Settings, etc.)
  if (isAdmin) return true;
  const features = Array.isArray(item.feature) ? item.feature : [item.feature];
  if (features.some((f) => access.has(f))) return true;
  if (item.altFeature && access.has(item.altFeature)) return true;
  return false;
}
