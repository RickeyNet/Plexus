/**
 * Whether the page is hidden (a background tab, a minimised window), and a
 * subscription to changes. Without a document (tests, workers) the page
 * counts as visible and nothing changes.
 */
export function pageHidden(): boolean {
  return typeof document !== 'undefined' && document.visibilityState === 'hidden';
}

/** Call `onChange` whenever the page is hidden or shown again; returns the unsubscribe. */
export function onPageVisibilityChange(onChange: (hidden: boolean) => void): () => void {
  if (typeof document === 'undefined') return () => {};
  const listener = () => onChange(pageHidden());
  document.addEventListener('visibilitychange', listener);
  return () => document.removeEventListener('visibilitychange', listener);
}
