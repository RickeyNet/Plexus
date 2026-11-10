import type { ReactNode } from 'react';

export interface DataTableProps {
  /** The table's `<thead>` / `<tbody>`. */
  children: ReactNode;
  /** Denser rows (`.table-sm`). */
  compact?: boolean;
  /** Header row stays visible while the wrapper scrolls (`.table-sticky`). */
  stickyHeader?: boolean;
  /** Caps the wrapper's height (px or any CSS length) so long tables scroll inside it. */
  maxHeight?: number | string;
  className?: string;
  /** Accessible name when the table has no visible caption. */
  'aria-label'?: string;
}

/**
 * The canonical table: `.data-table` inside a horizontal-scroll wrapper
 * (`.table-scroll`), so wide tables scroll instead of overflowing the card.
 * A bare `<table className="data-table">` gets the same cell styling; use this
 * component when the table needs the scroll wrapper.
 */
export function DataTable({ children, compact, stickyHeader, maxHeight, className, ...rest }: DataTableProps) {
  const cls = ['data-table'];
  if (compact) cls.push('table-sm');
  if (stickyHeader) cls.push('table-sticky');
  if (className) cls.push(className);
  return (
    <div className="table-scroll" style={maxHeight != null ? { maxHeight, overflowY: 'auto' } : undefined}>
      <table className={cls.join(' ')} aria-label={rest['aria-label']}>
        {children}
      </table>
    </div>
  );
}
