import { describe, expect, it } from 'vitest';

import { formatCount } from './formatCount';

describe('formatCount', () => {
  it('adds thousands separators', () => {
    expect(formatCount(254)).toBe('254');
    expect(formatCount(65536)).toBe((65536).toLocaleString());
    expect(formatCount('16777216')).toBe((16777216).toLocaleString());
  });

  it('reads missing and non-numeric values as 0', () => {
    expect(formatCount(undefined)).toBe('0');
    expect(formatCount(null)).toBe('0');
    expect(formatCount('n/a')).toBe('0');
  });

  it('uses scientific notation for counts too large to show in full', () => {
    const v6 = formatCount(2 ** 64);
    expect(v6).toMatch(/E19$/);
    expect(v6.length).toBeLessThan(10);
    expect(formatCount(999_999_999_999)).toBe((999_999_999_999).toLocaleString());
  });
});
