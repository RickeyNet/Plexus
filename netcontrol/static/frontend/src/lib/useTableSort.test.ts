import { describe, expect, it } from 'vitest';

import {
  compareDate,
  compareNumber,
  compareText,
  nextSort,
  passRatio,
  sortRows,
  type Comparator,
} from './useTableSort';

interface Row {
  name: string;
  score: number | null;
  at: string | null;
}

const ROWS: Row[] = [
  { name: 'sw10', score: 2, at: '2026-07-07 12:00:00' },
  { name: 'sw2', score: null, at: '2026-07-08 09:00:00' },
  { name: 'Core-1', score: 5, at: null },
  { name: 'edge', score: 2, at: '2026-07-06T23:00:00+00:00' },
];

const COMPARATORS: Record<'name' | 'score' | 'at', Comparator<Row>> = {
  name: (a, b) => compareText(a.name, b.name),
  score: (a, b) => compareNumber(a.score, b.score),
  at: (a, b) => compareDate(a.at, b.at),
};

const names = (rows: Row[]) => rows.map((r) => r.name);

describe('comparators', () => {
  it('compares text case-insensitively and numerically', () => {
    expect(compareText('sw2', 'sw10')).toBeLessThan(0);
    expect(compareText('ABC', 'abc')).toBe(0);
    expect(compareText(null, 'a')).toBeLessThan(0);
  });

  it('sorts missing numbers and dates lowest', () => {
    expect(compareNumber(null, 0)).toBeLessThan(0);
    expect(compareNumber(Number.NaN, -5)).toBeLessThan(0);
    expect(compareNumber(3, 3)).toBe(0);
    expect(compareDate(null, '2026-07-07 12:00:00')).toBeLessThan(0);
    expect(compareDate('2026-07-07 12:00:00', '2026-07-07T12:00:00Z')).toBe(0);
  });

  it('computes the pass ratio', () => {
    expect(passRatio(3, 4)).toBe(0.75);
    expect(passRatio(0, 0)).toBe(0);
    expect(passRatio(undefined, 10)).toBe(0);
  });
});

describe('nextSort', () => {
  it('reverses the active column', () => {
    expect(nextSort({ key: 'name', dir: 'asc' }, 'name')).toEqual({ key: 'name', dir: 'desc' });
    expect(nextSort({ key: 'name', dir: 'desc' }, 'name')).toEqual({ key: 'name', dir: 'asc' });
  });

  it('starts a new column ascending unless told otherwise', () => {
    expect(nextSort({ key: 'name', dir: 'desc' }, 'score')).toEqual({ key: 'score', dir: 'asc' });
    expect(nextSort<'name' | 'at'>({ key: 'name', dir: 'asc' }, 'at', { at: 'desc' })).toEqual({
      key: 'at',
      dir: 'desc',
    });
  });
});

describe('sortRows', () => {
  it('sorts ascending and descending', () => {
    expect(names(sortRows(ROWS, COMPARATORS, { key: 'name', dir: 'asc' }))).toEqual([
      'Core-1',
      'edge',
      'sw2',
      'sw10',
    ]);
    expect(names(sortRows(ROWS, COMPARATORS, { key: 'at', dir: 'desc' }))).toEqual([
      'sw2',
      'sw10',
      'edge',
      'Core-1',
    ]);
  });

  it('keeps ties in original order without a tie-break', () => {
    expect(names(sortRows(ROWS, COMPARATORS, { key: 'score', dir: 'asc' }))).toEqual([
      'sw2',
      'sw10',
      'edge',
      'Core-1',
    ]);
  });

  it('applies the tie-break ascending in both directions', () => {
    const byName: Comparator<Row> = (a, b) => compareText(a.name, b.name);
    expect(names(sortRows(ROWS, COMPARATORS, { key: 'score', dir: 'desc' }, byName))).toEqual([
      'Core-1',
      'edge',
      'sw10',
      'sw2',
    ]);
  });

  it('does not mutate the input', () => {
    const copy = [...ROWS];
    sortRows(ROWS, COMPARATORS, { key: 'name', dir: 'desc' });
    expect(ROWS).toEqual(copy);
  });
});
