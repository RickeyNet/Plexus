import { describe, expect, it } from 'vitest';

import { parseBoundedInt } from './numberInput';

describe('parseBoundedInt', () => {
  it('returns in-range integers unchanged', () => {
    expect(parseBoundedInt('1', 1, 8, 4)).toBe(1);
    expect(parseBoundedInt(' 6 ', 1, 8, 4)).toBe(6);
    expect(parseBoundedInt('0', 0, 5, 2)).toBe(0);
  });

  it('clamps out-of-range values to the bounds', () => {
    expect(parseBoundedInt('0', 1, 8, 4)).toBe(1);
    expect(parseBoundedInt('-3', 1, 8, 4)).toBe(1);
    expect(parseBoundedInt('99', 1, 8, 4)).toBe(8);
  });

  it('falls back when the field is blank or not a number', () => {
    expect(parseBoundedInt('', 1, 8, 4)).toBe(4);
    expect(parseBoundedInt('   ', 1, 8, 4)).toBe(4);
    expect(parseBoundedInt('abc', 0, 5, 2)).toBe(2);
  });

  it('truncates decimals', () => {
    expect(parseBoundedInt('2.9', 1, 8, 4)).toBe(2);
  });
});
