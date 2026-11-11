import type { CSSProperties, ReactNode } from 'react';

import type { SortState } from '@/lib/useTableSort';

interface SortableThProps<K extends string> {
  /** The column this header sorts by. */
  sortKey: K;
  /** Current sort, from useTableSort. */
  sort: SortState<K>;
  /** Called with `sortKey` on click (useTableSort's `toggle`). */
  onSort: (key: K) => void;
  children: ReactNode;
  title?: string;
  className?: string;
  style?: CSSProperties;
}

/**
 * A sortable column header: a real button inside the `<th>`, with `aria-sort`
 * on the cell and an arrow on the active column. Click to sort, click again to
 * reverse.
 */
export function SortableTh<K extends string>({
  sortKey,
  sort,
  onSort,
  children,
  title,
  className,
  style,
}: SortableThProps<K>) {
  const active = sort.key === sortKey;
  const ariaSort = active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none';
  return (
    <th aria-sort={ariaSort} className={className} style={style}>
      <button type="button" className="th-sort" title={title} onClick={() => onSort(sortKey)}>
        {children}
        <span className="th-sort-icon" aria-hidden="true">
          {active ? (sort.dir === 'asc' ? '▲' : '▼') : ''}
        </span>
      </button>
    </th>
  );
}
