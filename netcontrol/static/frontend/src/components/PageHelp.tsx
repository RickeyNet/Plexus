import { useState } from 'react';

const STORAGE_KEY = 'plexus_help_dismissed';

interface Props {
  pageKey: string;
  title: string;
  text: string;
}

function loadDismissed(): Record<string, boolean> {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '{}');
  } catch {
    return {};
  }
}

function saveDismissed(d: Record<string, boolean>): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(d));
  } catch {
    /* private mode */
  }
}

export function PageHelp({ pageKey, title, text }: Props) {
  const [collapsed, setCollapsed] = useState<boolean>(() => !!loadDismissed()[pageKey]);

  const [prevPageKey, setPrevPageKey] = useState(pageKey);
  // Re-read the dismissed state from storage when the page key changes.
  if (pageKey !== prevPageKey) {
    setPrevPageKey(pageKey);
    setCollapsed(!!loadDismissed()[pageKey]);
  }

  function toggle() {
    setCollapsed((prev) => {
      const next = !prev;
      const d = loadDismissed();
      if (next) d[pageKey] = true;
      else delete d[pageKey];
      saveDismissed(d);
      return next;
    });
  }

  return (
    <div className={`page-help${collapsed ? ' page-help-collapsed' : ''}`}>
      <div className="page-help-content">
        <svg className="page-help-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10" />
          <line x1="12" y1="16" x2="12" y2="12" />
          <line x1="12" y1="8" x2="12.01" y2="8" />
        </svg>
        <div>
          <strong>{title}</strong>
          <span className="page-help-text"> &mdash; {text}</span>
        </div>
      </div>
      <button
        type="button"
        className="page-help-toggle"
        title={collapsed ? 'Show help' : 'Hide help'}
        onClick={toggle}
        aria-label={collapsed ? 'Show help' : 'Hide help'}
      >
        {collapsed ? '?' : '×'}
      </button>
    </div>
  );
}
