import type { ReactNode } from 'react';

export interface TabBarItem<K extends string = string> {
  key: K;
  label: ReactNode;
  /** Optional count or status badge rendered after the label. */
  badge?: ReactNode;
  disabled?: boolean;
  title?: string;
}

interface TabBarProps<K extends string> {
  tabs: readonly TabBarItem<K>[];
  active: K;
  onChange: (key: K) => void;
  /** Visual size. `md` is the page-level tab row; `sm` is for nested sub-tabs. */
  size?: 'md' | 'sm';
  /** Extra controls rendered at the right end of the bar (search box, buttons). */
  trailing?: ReactNode;
  className?: string;
  'aria-label'?: string;
}

/**
 * Page and section tab row. One shared implementation for the ~20 hand-rolled
 * `role="tablist"` button groups that used to live in each page. Renders
 * `.btn.btn-sm.btn-secondary.page-tab-btn[.active]` so the legacy stylesheet's
 * gradient active state applies without per-page CSS classes.
 *
 * Tab *state* is the caller's: pages with URL-addressable tabs read it from the
 * path (`/page/<tab>`) and call `navigate()` from `onChange`.
 */
export function TabBar<K extends string>({
  tabs,
  active,
  onChange,
  size = 'md',
  trailing,
  className,
  'aria-label': ariaLabel,
}: TabBarProps<K>) {
  return (
    <div
      role="tablist"
      aria-label={ariaLabel}
      className={`tab-bar tab-bar-${size}${className ? ` ${className}` : ''}`}
    >
      {tabs.map((t) => {
        const isActive = t.key === active;
        return (
          <button
            key={t.key}
            type="button"
            role="tab"
            aria-selected={isActive}
            disabled={t.disabled}
            title={t.title}
            className={`btn btn-sm btn-secondary page-tab-btn${isActive ? ' active' : ''}`}
            onClick={() => !t.disabled && onChange(t.key)}
          >
            {t.label}
            {t.badge !== undefined && t.badge !== null && (
              <span className="tab-bar-badge">{t.badge}</span>
            )}
          </button>
        );
      })}
      {trailing && <div className="tab-bar-trailing">{trailing}</div>}
    </div>
  );
}
