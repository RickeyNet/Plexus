import type { ReactNode } from 'react';

interface PageHeaderProps {
  /** Page name. A string in most pages; a node when it carries a badge or back link. */
  title: ReactNode;
  /** Buttons and controls shown at the right end of the header. */
  children?: ReactNode;
  className?: string;
}

/**
 * The one page-title row: `.page-header` with an `h2.page-title` on the left
 * and the page's actions on the right. Every top-level page renders this
 * rather than a hand-built `<h2>`, so the title size, colour treatment and the
 * gap below it are the same everywhere.
 */
export function PageHeader({ title, children, className }: PageHeaderProps) {
  return (
    <div className={`page-header${className ? ` ${className}` : ''}`}>
      <h2 className="page-title">{title}</h2>
      {children && <div className="page-header-actions">{children}</div>}
    </div>
  );
}
