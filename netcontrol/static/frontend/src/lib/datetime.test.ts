import { describe, expect, it } from 'vitest';

import {
  formatBackendDate,
  formatBackendDateTime,
  formatBackendTime,
  formatBackendTimestamp,
  formatInterval,
  formatRelativeTime,
  localInputToIso,
  parseBackendDate,
  toDate,
  toLocalInputValue,
} from './datetime';

// 2026-07-07 12:00:05 UTC: the instant every naive fixture below means.
const NOON_UTC = new Date(Date.UTC(2026, 6, 7, 12, 0, 5));

describe('parseBackendDate', () => {
  it('parses a naive backend timestamp as UTC, not local', () => {
    // "YYYY-MM-DD HH:MM:SS" with no zone must be read as UTC.
    const d = parseBackendDate('2026-07-07 12:00:00');
    expect(d).not.toBeNull();
    expect(d!.toISOString()).toBe('2026-07-07T12:00:00.000Z');
  });

  it('handles the T separator too', () => {
    const d = parseBackendDate('2026-07-07T12:00:00');
    expect(d!.toISOString()).toBe('2026-07-07T12:00:00.000Z');
  });

  it('respects an explicit timezone suffix', () => {
    const d = parseBackendDate('2026-07-07T12:00:00+00:00');
    expect(d!.toISOString()).toBe('2026-07-07T12:00:00.000Z');
    expect(parseBackendDate('2026-07-07T14:00:00+02:00')!.toISOString()).toBe('2026-07-07T12:00:00.000Z');
    expect(parseBackendDate('2026-07-07T12:00:00Z')!.toISOString()).toBe('2026-07-07T12:00:00.000Z');
  });

  it('parses Postgres text stamps with an hours-only offset', () => {
    // A TEXT column filled by NOW() holds "YYYY-MM-DD HH:MM:SS.ffffff+00".
    expect(parseBackendDate('2026-07-07 12:00:00.123456+00')!.toISOString()).toBe('2026-07-07T12:00:00.123Z');
    expect(parseBackendDate('2026-07-07 14:00:00-02')!.toISOString()).toBe('2026-07-07T16:00:00.000Z');
  });

  it('parses Python isoformat with microseconds', () => {
    expect(parseBackendDate('2026-07-07T12:00:00.123456+00:00')!.toISOString()).toBe('2026-07-07T12:00:00.123Z');
  });

  it('keeps a bare date on the same calendar day in any timezone', () => {
    const d = parseBackendDate('2026-07-07')!;
    expect([d.getFullYear(), d.getMonth(), d.getDate()]).toEqual([2026, 6, 7]);
  });

  it('returns null for empty or invalid input', () => {
    expect(parseBackendDate('')).toBeNull();
    expect(parseBackendDate(null)).toBeNull();
    expect(parseBackendDate(undefined)).toBeNull();
    expect(parseBackendDate('not-a-date')).toBeNull();
  });
});

describe('toDate', () => {
  it('accepts strings, epoch milliseconds and Dates', () => {
    expect(toDate('2026-07-07 12:00:05')!.getTime()).toBe(NOON_UTC.getTime());
    expect(toDate(NOON_UTC.getTime())!.getTime()).toBe(NOON_UTC.getTime());
    expect(toDate(NOON_UTC)!.getTime()).toBe(NOON_UTC.getTime());
  });

  it('returns null for missing or invalid values', () => {
    expect(toDate(null)).toBeNull();
    expect(toDate('')).toBeNull();
    expect(toDate(new Date(NaN))).toBeNull();
    expect(toDate(Number.NaN)).toBeNull();
  });
});

describe('display formatters', () => {
  // Expected strings are built with the same options in the runner's locale
  // and timezone, so the assertions hold on any machine.
  const expectFmt = (opts: Intl.DateTimeFormatOptions) => NOON_UTC.toLocaleString(undefined, opts);

  it('formatBackendDateTime shows date and time to the minute', () => {
    expect(formatBackendDateTime('2026-07-07 12:00:05')).toBe(
      expectFmt({ year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }),
    );
  });

  it('formatBackendTimestamp adds seconds', () => {
    expect(formatBackendTimestamp('2026-07-07T12:00:05+00:00')).toBe(
      expectFmt({
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        second: '2-digit',
      }),
    );
  });

  it('formatBackendDate shows the date only', () => {
    expect(formatBackendDate(NOON_UTC)).toBe(expectFmt({ year: 'numeric', month: 'short', day: 'numeric' }));
  });

  it('formatBackendTime shows the time of day only', () => {
    expect(formatBackendTime(NOON_UTC.getTime())).toBe(
      expectFmt({ hour: 'numeric', minute: '2-digit', second: '2-digit' }),
    );
  });

  it('reads a naive value as UTC (same output as the explicit-zone value)', () => {
    expect(formatBackendDateTime('2026-07-07 12:00:05')).toBe(formatBackendDateTime('2026-07-07T12:00:05Z'));
  });

  it('falls back for missing values', () => {
    expect(formatBackendDateTime(null)).toBe('-');
    expect(formatBackendDateTime(undefined, 'N/A')).toBe('N/A');
    expect(formatBackendDate(null, 'never')).toBe('never');
    expect(formatBackendTime('')).toBe('-');
    expect(formatBackendTimestamp(undefined)).toBe('-');
  });

  it('shows an unparseable string as-is', () => {
    expect(formatBackendDateTime('soon')).toBe('soon');
    expect(formatBackendDate('soon')).toBe('soon');
  });
});

describe('formatRelativeTime', () => {
  const now = Date.UTC(2026, 6, 7, 12, 0, 0);

  it('describes past spans in at most two units', () => {
    expect(formatRelativeTime(now - 30 * 1000, now)).toBe('just now');
    expect(formatRelativeTime(now - 45 * 60 * 1000, now)).toBe('45m ago');
    expect(formatRelativeTime(now - (3 * 3600 + 12 * 60) * 1000, now)).toBe('3h 12m ago');
    expect(formatRelativeTime(now - 26 * 3600 * 1000, now)).toBe('1d 2h ago');
  });

  it('describes future spans', () => {
    expect(formatRelativeTime(now + 30 * 1000, now)).toBe('in <1m');
    expect(formatRelativeTime(now + 45 * 60 * 1000, now)).toBe('in 45m');
    expect(formatRelativeTime(now + (2 * 3600 + 15 * 60) * 1000, now)).toBe('in 2h 15m');
  });

  it('reads backend strings as UTC', () => {
    expect(formatRelativeTime('2026-07-07 11:55:00', now)).toBe('5m ago');
    expect(formatRelativeTime('2026-07-07 11:55:00.000000+00', now)).toBe('5m ago');
  });

  it('falls back for missing values and echoes unparseable strings', () => {
    expect(formatRelativeTime(null, now)).toBe('-');
    expect(formatRelativeTime(undefined, now, 'Never')).toBe('Never');
    expect(formatRelativeTime('soon', now)).toBe('soon');
  });
});

describe('datetime-local input helpers', () => {
  it('formats an instant as the viewer-local input value', () => {
    const local = new Date(2026, 6, 7, 9, 5);
    expect(toLocalInputValue(local)).toBe('2026-07-07T09:05');
  });

  it('round-trips through localInputToIso', () => {
    const iso = localInputToIso('2026-07-07T09:05');
    expect(iso).toBe(new Date(2026, 6, 7, 9, 5).toISOString());
    expect(toLocalInputValue(iso)).toBe('2026-07-07T09:05');
  });

  it('returns empty strings for missing or invalid values', () => {
    expect(toLocalInputValue(null)).toBe('');
    expect(toLocalInputValue('not-a-date')).toBe('');
    expect(localInputToIso('')).toBe('');
    expect(localInputToIso('not-a-date')).toBe('');
  });
});

describe('formatInterval', () => {
  it('formats whole-day intervals', () => {
    expect(formatInterval(86400)).toBe('1d');
    expect(formatInterval(86400 * 7)).toBe('7d');
  });

  it('formats whole-hour intervals', () => {
    expect(formatInterval(3600)).toBe('1h');
    expect(formatInterval(3600 * 6)).toBe('6h');
  });

  it('formats minutes and seconds', () => {
    expect(formatInterval(900)).toBe('15m');
    expect(formatInterval(45)).toBe('45s');
  });

  it('returns dash for null/zero', () => {
    expect(formatInterval(null)).toBe('-');
    expect(formatInterval(undefined)).toBe('-');
    expect(formatInterval(0)).toBe('-');
  });
});
