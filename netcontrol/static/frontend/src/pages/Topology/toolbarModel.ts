export type LayoutMode =
  | 'tidy'
  | 'physics'
  | 'circular'
  | 'hierarchical-UD'
  | 'hierarchical-DU'
  | 'hierarchical-LR'
  | 'hierarchical-RL';

export const LAYOUT_OPTIONS: readonly { value: LayoutMode; label: string }[] = [
  { value: 'tidy', label: 'Tidy tree (top→bottom)' },
  { value: 'physics', label: 'Physics (force-directed)' },
  { value: 'circular', label: 'Circular' },
  { value: 'hierarchical-UD', label: 'Hierarchical (top→bottom)' },
  { value: 'hierarchical-DU', label: 'Hierarchical (bottom→top)' },
  { value: 'hierarchical-LR', label: 'Hierarchical (left→right)' },
  { value: 'hierarchical-RL', label: 'Hierarchical (right→left)' },
];

export function layoutLabel(mode: LayoutMode): string {
  return LAYOUT_OPTIONS.find((o) => o.value === mode)?.label ?? mode;
}

export interface Overlays {
  util: boolean;
  stp: boolean;
  status: boolean;
}

/** How many map overlays are on, for the badge on the View trigger. */
export function enabledOverlayCount(o: Overlays): number {
  return [o.util, o.stp, o.status].filter(Boolean).length;
}

/** Badge text for an unacknowledged count: null hides the badge. */
export function badgeText(count: number): string | null {
  if (count <= 0) return null;
  return count > 99 ? '99+' : String(count);
}
