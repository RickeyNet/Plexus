import { describe, expect, it } from 'vitest';

import {
  DEFAULT_TIME_RANGE,
  clampPreset,
  isTimeRangePreset,
  parseStoredTimeRange,
  toDays,
  toHours,
} from './timeRangeMap';

describe('toHours', () => {
  it('maps every preset to hours', () => {
    expect(toHours('1h')).toBe(1);
    expect(toHours('6h')).toBe(6);
    expect(toHours('24h')).toBe(24);
    expect(toHours('7d')).toBe(168);
    expect(toHours('30d')).toBe(720);
  });
});

describe('toDays', () => {
  it('rounds sub-day presets up to one day', () => {
    expect(toDays('1h')).toBe(1);
    expect(toDays('6h')).toBe(1);
    expect(toDays('24h')).toBe(1);
  });
  it('maps multi-day presets', () => {
    expect(toDays('7d')).toBe(7);
    expect(toDays('30d')).toBe(30);
  });
});

describe('clampPreset', () => {
  const upTo7d = ['1h', '6h', '24h', '7d'] as const;

  it('passes allowed presets through', () => {
    expect(clampPreset('6h', upTo7d)).toBe('6h');
    expect(clampPreset('7d', upTo7d)).toBe('7d');
  });
  it('clamps down to the largest allowed preset', () => {
    expect(clampPreset('30d', upTo7d)).toBe('7d');
    expect(clampPreset('7d', ['1h', '24h'] as const)).toBe('24h');
  });
  it('picks the nearest shorter preset when the exact one is missing', () => {
    expect(clampPreset('6h', ['1h', '24h'] as const)).toBe('1h');
  });
  it('falls back to the smallest allowed preset when all are longer', () => {
    expect(clampPreset('1h', ['24h', '7d'] as const)).toBe('24h');
  });
  it('does not depend on the order of allowed', () => {
    expect(clampPreset('30d', ['7d', '1h', '24h'] as const)).toBe('7d');
  });
  it('rejects an empty allowed list', () => {
    expect(() => clampPreset('1h', [])).toThrow();
  });
});

describe('stored range parsing', () => {
  it('recognizes presets', () => {
    expect(isTimeRangePreset('24h')).toBe(true);
    expect(isTimeRangePreset('custom')).toBe(false);
    expect(isTimeRangePreset(24)).toBe(false);
  });
  it('returns a stored preset', () => {
    expect(parseStoredTimeRange('7d')).toBe('7d');
  });
  it('falls back to the default for missing or junk values', () => {
    expect(parseStoredTimeRange(null)).toBe(DEFAULT_TIME_RANGE);
    expect(parseStoredTimeRange('custom')).toBe(DEFAULT_TIME_RANGE);
    expect(parseStoredTimeRange('')).toBe(DEFAULT_TIME_RANGE);
  });
});
