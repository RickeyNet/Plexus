import { useCallback, useMemo, useState } from 'react';

import { parseBackendDate } from '@/lib/datetime';

// Client-side column sorting for a table: which column, which direction,
// and the rows in that order. Pair with <SortableTh> for the header cells.

export type SortDir = 'asc' | 'desc';

export interface SortState<K extends string> {
  key: K;
  dir: SortDir;
}

/** Ascending comparator; the hook reverses it for descending order. */
export type Comparator<T> = (a: T, b: T) => number;

/** Text, case-insensitive and numeric-aware ("sw2" before "sw10"); missing sorts as empty. */
export function compareText(a: string | null | undefined, b: string | null | undefined): number {
  return (a ?? '').localeCompare(b ?? '', undefined, { sensitivity: 'base', numeric: true });
}

/** Numbers; missing or NaN sorts below every number. */
export function compareNumber(a: number | null | undefined, b: number | null | undefined): number {
  const x = a == null || Number.isNaN(a) ? -Infinity : a;
  const y = b == null || Number.isNaN(b) ? -Infinity : b;
  return x === y ? 0 : x < y ? -1 : 1;
}

/** Backend timestamps (see parseBackendDate); missing or unparseable sorts oldest. */
export function compareDate(a: string | null | undefined, b: string | null | undefined): number {
  return compareNumber(parseBackendDate(a)?.getTime(), parseBackendDate(b)?.getTime());
}

/** passed/total as a ratio, for score columns; a zero total counts as 0. */
export function passRatio(passed: number | null | undefined, total: number | null | undefined): number {
  return total ? (passed ?? 0) / total : 0;
}

/**
 * The next sort after a header click: the active column flips direction,
 * another column starts at its preferred first direction (ascending unless
 * `firstDir` says otherwise, e.g. newest-first for dates).
 */
export function nextSort<K extends string>(
  current: SortState<K>,
  key: K,
  firstDir: Partial<Record<K, SortDir>> = {},
): SortState<K> {
  if (current.key === key) return { key, dir: current.dir === 'asc' ? 'desc' : 'asc' };
  return { key, dir: firstDir[key] ?? 'asc' };
}

/**
 * A sorted copy of `rows`. Ties fall back to `tieBreak` (always ascending,
 * so the secondary order stays readable when the primary is reversed), then
 * to the original order.
 */
export function sortRows<T, K extends string>(
  rows: readonly T[],
  comparators: Record<K, Comparator<T>>,
  sort: SortState<K>,
  tieBreak?: Comparator<T>,
): T[] {
  const cmp = comparators[sort.key];
  const sign = sort.dir === 'asc' ? 1 : -1;
  return rows
    .map((row, index) => ({ row, index }))
    .sort((a, b) => {
      const primary = cmp ? cmp(a.row, b.row) * sign : 0;
      if (primary !== 0) return primary;
      const secondary = tieBreak ? tieBreak(a.row, b.row) : 0;
      return secondary !== 0 ? secondary : a.index - b.index;
    })
    .map((x) => x.row);
}

export interface TableSortOptions<T, K extends string> {
  /** Direction a column starts in when first clicked (default ascending). */
  firstDir?: Partial<Record<K, SortDir>>;
  /** Secondary order for rows the active column ranks equal. */
  tieBreak?: Comparator<T>;
}

export interface TableSort<T, K extends string> {
  rows: T[];
  sort: SortState<K>;
  /** Header click handler: sort by `key`, or reverse it when already active. */
  toggle: (key: K) => void;
}

/**
 * Sort state plus the sorted rows. `comparators` maps each sortable column
 * key to an ascending comparator; keep it a module constant (or memoised) so
 * the rows are not re-sorted on every render.
 *
 *   const { rows, sort, toggle } = useTableSort(filtered, COMPARATORS, { key: 'scanned', dir: 'desc' });
 *   <SortableTh sortKey="scanned" sort={sort} onSort={toggle}>Scanned</SortableTh>
 */
export function useTableSort<T, K extends string>(
  items: readonly T[],
  comparators: Record<K, Comparator<T>>,
  initial: SortState<K>,
  options: TableSortOptions<T, K> = {},
): TableSort<T, K> {
  const [sort, setSort] = useState<SortState<K>>(initial);
  const { firstDir, tieBreak } = options;
  const toggle = useCallback((key: K) => setSort((cur) => nextSort(cur, key, firstDir)), [firstDir]);
  const rows = useMemo(
    () => sortRows(items, comparators, sort, tieBreak),
    [items, comparators, sort, tieBreak],
  );
  return { rows, sort, toggle };
}
