import { describe, expect, it } from 'vitest';

import { stpStyle, utilColor, utilShadow, type TopoStatusColors } from './helpers';

const STATUS: TopoStatusColors = {
  success: '#008000',
  warning: '#ff8000',
  danger: '#ff0000',
  info: '#0000ff',
  violet: '#800080',
  muted: '#808080',
};

describe('utilColor', () => {
  it('runs from the theme success color through warning to danger', () => {
    expect(utilColor(0, STATUS).color).toBe('#008000');
    expect(utilColor(50, STATUS).color).toBe('#ff8000');
    expect(utilColor(100, STATUS).color).toBe('#ff0000');
    expect(utilColor(75, STATUS)).toEqual({ color: '#ff4000', highlight: '#ff4000', hover: '#ff4000', opacity: 0.9 });
  });
});

describe('utilShadow', () => {
  it('tints the shadow with the band the utilization is in', () => {
    expect(utilShadow(10, STATUS)).toBe('rgba(0,128,0,0.3)');
    expect(utilShadow(60, STATUS)).toBe('rgba(255,128,0,0.3)');
    expect(utilShadow(90, STATUS)).toBe('rgba(255,0,0,0.4)');
  });
});

describe('stpStyle', () => {
  it('colors each port state from the theme status colors', () => {
    expect(stpStyle('forwarding', STATUS)?.color.color).toBe('#008000');
    expect(stpStyle('LEARNING', STATUS)?.color.color).toBe('#ff8000');
    expect(stpStyle('blocking', STATUS)).toEqual({
      color: { color: '#ff0000', highlight: '#ff0000', hover: '#ff0000', opacity: 0.95 },
      width: 6,
      dashes: [4, 3],
      shadow: 'rgba(255,0,0,0.45)',
    });
    expect(stpStyle('unknown', STATUS)).toBeNull();
  });
});
