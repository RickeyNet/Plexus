import { useState } from 'react';

/**
 * Caps how many rows a table renders at once. Thousands of <tr> elements
 * freeze the tab; this renders the first `step` and grows on demand.
 *
 * The limit intentionally never auto-resets when `items` changes — interval
 * refetches replace the array identity every cycle, and collapsing the
 * user's expanded view on each poll would be worse than showing a longer
 * list after a new search.
 */
export function useShowMore<T>(items: T[], step = 200) {
  const [limit, setLimit] = useState(step);
  return {
    visible: items.length > limit ? items.slice(0, limit) : items,
    hiddenCount: Math.max(0, items.length - limit),
    showMore: () => setLimit((l) => l + step),
  };
}
