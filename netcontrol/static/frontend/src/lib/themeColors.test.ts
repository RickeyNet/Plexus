import { describe, expect, it } from 'vitest';

import { mixColors, parseRgb, resolveThemeVars, withAlpha } from './themeColors';

const TOKENS: Record<string, string> = {
  '--text': '#1f2c1f',
  '--danger': '#b83232',
  '--info': 'rgb(30, 90, 200)',
};
const lookup = (name: string) => TOKENS[name] ?? '';

describe('resolveThemeVars', () => {
  it('replaces tokens deep inside an option', () => {
    const option = {
      legend: { textStyle: { color: 'var(--text)' } },
      series: [{ itemStyle: { color: 'var(--danger)' } }, { lineStyle: { color: 'var(--info)' } }],
    };
    expect(resolveThemeVars(option, lookup)).toEqual({
      legend: { textStyle: { color: '#1f2c1f' } },
      series: [{ itemStyle: { color: '#b83232' } }, { lineStyle: { color: 'rgb(30, 90, 200)' } }],
    });
  });

  it('uses the fallback of an unset token and leaves an unknown one as written', () => {
    expect(resolveThemeVars('var(--missing, #123456)', lookup)).toBe('#123456');
    expect(resolveThemeVars('var(--missing, rgba(0,0,0,0.5))', lookup)).toBe('rgba(0,0,0,0.5)');
    expect(resolveThemeVars('var(--missing)', lookup)).toBe('var(--missing)');
  });

  it('keeps functions, numbers and untouched branches as they are', () => {
    const formatter = (v: number) => String(v);
    const data = [[1, 2], [3, 4]];
    const option = { axisLabel: { formatter, color: 'var(--text)' }, data, width: 2 };
    const out = resolveThemeVars(option, lookup);
    expect(out.axisLabel.formatter).toBe(formatter);
    expect(out.data).toBe(data);
    expect(out.width).toBe(2);
    expect(out).not.toBe(option);
  });
});

describe('parseRgb / withAlpha', () => {
  it('reads hex and rgb() colors', () => {
    expect(parseRgb('#fff')).toEqual([255, 255, 255]);
    expect(parseRgb('#B83232')).toEqual([184, 50, 50]);
    expect(parseRgb('#b83232cc')).toEqual([184, 50, 50]);
    expect(parseRgb('rgba(1, 2, 3, 0.5)')).toEqual([1, 2, 3]);
    expect(parseRgb('rgb(1 2 3)')).toEqual([1, 2, 3]);
    expect(parseRgb('teal')).toBeNull();
  });

  it('sets the alpha, leaving an unreadable color alone', () => {
    expect(withAlpha('#b83232', 0.4)).toBe('rgba(184,50,50,0.4)');
    expect(withAlpha('rgb(30, 90, 200)', 0.25)).toBe('rgba(30,90,200,0.25)');
    expect(withAlpha('teal', 0.4)).toBe('teal');
  });
});

describe('mixColors', () => {
  it('interpolates between two colors', () => {
    expect(mixColors('#000000', '#ffffff', 0)).toBe('#000000');
    expect(mixColors('#000000', '#ffffff', 1)).toBe('#ffffff');
    expect(mixColors('#000000', '#ff8000', 0.5)).toBe('#804000');
  });

  it('clamps t and falls back to the nearer color when one cannot be parsed', () => {
    expect(mixColors('#000000', '#ffffff', 2)).toBe('#ffffff');
    expect(mixColors('teal', '#ffffff', 0.2)).toBe('teal');
    expect(mixColors('teal', '#ffffff', 0.8)).toBe('#ffffff');
  });
});
