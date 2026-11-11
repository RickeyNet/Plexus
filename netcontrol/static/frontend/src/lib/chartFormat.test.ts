import { describe, expect, it } from 'vitest';

import { chartTooltipFormatter, formatBpsTick, formatBpsValue, formatChartNumber } from './chartFormat';

describe('formatBpsTick / formatBpsValue', () => {
  it('scales to an SI prefix with one decimal', () => {
    expect(formatBpsTick(1_234_567_890)).toBe('1.2G');
    expect(formatBpsValue(1_234_567_890)).toBe('1.2 Gbps');
    expect(formatBpsValue(2_500_000)).toBe('2.5 Mbps');
    expect(formatBpsValue(1_500)).toBe('1.5 kbps');
  });

  it('leaves small values unscaled', () => {
    expect(formatBpsTick(512)).toBe('512');
    expect(formatBpsValue(512)).toBe('512 bps');
    expect(formatBpsValue(0)).toBe('0 bps');
  });
});

describe('formatChartNumber', () => {
  it('rounds to at most two decimals', () => {
    expect(formatChartNumber(12.3456)).toBe('12.35');
    expect(formatChartNumber(7)).toBe('7');
  });
});

describe('chartTooltipFormatter', () => {
  it('formats the y value of a [time, value] point', () => {
    expect(chartTooltipFormatter('bps')(['2026-01-01T00:00:00Z', 3_000_000])).toBe('3.0 Mbps');
    expect(chartTooltipFormatter('number')(41.666)).toBe('41.67');
  });

  it('shows a dash for a gap', () => {
    expect(chartTooltipFormatter('number')(null)).toBe('-');
    expect(chartTooltipFormatter('bps')(undefined)).toBe('-');
    expect(chartTooltipFormatter('number')('')).toBe('-');
  });

  it('uses a caller formatter for the y value and still dashes a gap', () => {
    const fmt = chartTooltipFormatter((v) => `${v} B`);
    expect(fmt(['2026-01-01T00:00:00Z', 512])).toBe('512 B');
    expect(fmt('2048')).toBe('2048 B');
    expect(fmt(null)).toBe('-');
  });
});
