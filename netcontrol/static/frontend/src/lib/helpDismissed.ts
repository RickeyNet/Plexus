// Per-page "dismissed" flags for in-page guidance (PageHelp intros, the
// Dashboard's setup guide), kept together in one localStorage entry so every
// dismissal is stored and cleared the same way.

const STORAGE_KEY = 'plexus_help_dismissed';

function loadDismissed(): Record<string, boolean> {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '{}');
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, boolean>) : {};
  } catch {
    return {};
  }
}

/** Whether the guidance stored under `key` was dismissed in this browser. */
export function isHelpDismissed(key: string): boolean {
  return !!loadDismissed()[key];
}

/** Remember (or forget) that the guidance under `key` was dismissed. */
export function setHelpDismissed(key: string, dismissed: boolean): void {
  const d = loadDismissed();
  if (dismissed) d[key] = true;
  else delete d[key];
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(d));
  } catch {
    /* private mode */
  }
}
