import { describe, expect, it } from 'vitest';

import { formatBackendDate, formatBackendDateTime, parseBackendDate } from './datetime';

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
  });

  it('returns null for empty or invalid input', () => {
    expect(parseBackendDate('')).toBeNull();
    expect(parseBackendDate(null)).toBeNull();
    expect(parseBackendDate(undefined)).toBeNull();
    expect(parseBackendDate('not-a-date')).toBeNull();
  });
});

describe('formatBackendDateTime / formatBackendDate', () => {
  it('falls back for missing values', () => {
    expect(formatBackendDateTime(null)).toBe('-');
    expect(formatBackendDateTime(undefined, 'N/A')).toBe('N/A');
    expect(formatBackendDate(null, 'never')).toBe('never');
  });

  it('formats a parseable timestamp (non-empty, not the fallback)', () => {
    const out = formatBackendDateTime('2026-07-07 12:00:00');
    expect(out).not.toBe('-');
    expect(out.length).toBeGreaterThan(0);
  });
});
