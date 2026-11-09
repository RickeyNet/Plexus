// Theme colors for canvas renderers. The app's themes are CSS custom
// properties on <html> (data-theme selects the set). DOM styles can use
// `var(--token)` directly, but a canvas (ECharts' canvas renderer, vis-network,
// a 2D context) cannot: it ignores any color string it cannot parse. These
// helpers turn tokens into concrete colors and tell a component when the theme
// changes so it can redraw with the new ones.

import { useSyncExternalStore } from 'react';

/** Looks up a custom property (`--name`) and returns its value, '' when unset. */
export type TokenLookup = (name: string) => string;

function documentLookup(): TokenLookup {
  if (typeof document === 'undefined') return () => '';
  const style = getComputedStyle(document.documentElement);
  return (name) => style.getPropertyValue(name).trim();
}

/** The current theme's value of `--name` as a concrete color, or `fallback` when it is unset. */
export function themeColor(name: string, fallback = ''): string {
  return documentLookup()(name) || fallback;
}

/**
 * A reader bound to the current theme, for code that reads many tokens at
 * once (one getComputedStyle call instead of one per token).
 */
export function themeColorReader(): (name: string, fallback?: string) => string {
  const lookup = documentLookup();
  return (name, fallback = '') => lookup(name) || fallback;
}

const VAR_RE = /var\(\s*(--[\w-]+)\s*(?:,\s*([^()]*(?:\([^()]*\)[^()]*)*))?\)/g;

function resolveString(value: string, lookup: TokenLookup): string {
  if (!value.includes('var(')) return value;
  return value.replace(VAR_RE, (whole, name: string, fallback?: string) => lookup(name) || fallback?.trim() || whole);
}

function resolveDeep(value: unknown, lookup: TokenLookup): unknown {
  if (typeof value === 'string') return resolveString(value, lookup);
  if (Array.isArray(value)) {
    let changed = false;
    const out = value.map((item) => {
      const next = resolveDeep(item, lookup);
      if (next !== item) changed = true;
      return next;
    });
    return changed ? out : value;
  }
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    let changed = false;
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      const next = resolveDeep(item, lookup);
      if (next !== item) changed = true;
      out[key] = next;
    }
    return changed ? out : value;
  }
  return value;
}

/**
 * Replaces every `var(--token)` (or `var(--token, fallback)`) inside the
 * strings of `value` (plain objects and arrays, walked deeply) with the
 * current theme's color. Untouched branches keep their identity. Use it on an
 * ECharts option or any other canvas style object written with tokens.
 */
export function resolveThemeVars<T>(value: T, lookup: TokenLookup = documentLookup()): T {
  return resolveDeep(value, lookup) as T;
}

/** The red, green and blue of `#rgb`, `#rrggbb`, `#rrggbbaa` or `rgb()`/`rgba()`; null for anything else. */
export function parseRgb(color: string): [number, number, number] | null {
  const c = color.trim();
  const hex = /^#([0-9a-f]{3}|[0-9a-f]{6}|[0-9a-f]{8})$/i.exec(c);
  if (hex) {
    let h = hex[1];
    if (h.length === 3) h = h.split('').map((ch) => ch + ch).join('');
    const [r, g, b] = [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
    return [r, g, b];
  }
  const rgb = /^rgba?\(\s*(\d{1,3})[\s,]+(\d{1,3})[\s,]+(\d{1,3})/i.exec(c);
  if (rgb) return [Number(rgb[1]), Number(rgb[2]), Number(rgb[3])];
  return null;
}

/** `color` with its alpha set to `alpha`, as `rgba(...)`; a color parseRgb cannot read comes back unchanged. */
export function withAlpha(color: string, alpha: number): string {
  const rgb = parseRgb(color);
  return rgb ? `rgba(${rgb[0]},${rgb[1]},${rgb[2]},${alpha})` : color;
}

/**
 * The color `t` of the way from `from` (t = 0) to `to` (t = 1), as `#rrggbb`.
 * When either color cannot be parsed the nearer one comes back unchanged.
 */
export function mixColors(from: string, to: string, t: number): string {
  const a = parseRgb(from);
  const b = parseRgb(to);
  if (!a || !b) return t < 0.5 ? from : to;
  const k = Math.max(0, Math.min(1, t));
  return `#${a.map((v, i) => Math.round(v + (b[i] - v) * k).toString(16).padStart(2, '0')).join('')}`;
}

// ── Theme change subscription ─────────────────────────────────────────────

function readThemeName(): string {
  if (typeof document === 'undefined') return '';
  return document.documentElement.getAttribute('data-theme') ?? '';
}

/** Calls `onChange` whenever `data-theme` on <html> changes; returns the unsubscribe. */
export function subscribeThemeChange(onChange: () => void): () => void {
  if (typeof MutationObserver === 'undefined' || typeof document === 'undefined') return () => {};
  const observer = new MutationObserver(onChange);
  observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
  return () => observer.disconnect();
}

/**
 * The active theme name. A component that draws on a canvas lists it in its
 * effect dependencies so it redraws with the new colors when the theme changes.
 */
export function useThemeName(): string {
  return useSyncExternalStore(subscribeThemeChange, readThemeName, () => '');
}

// ── Shared semantic palettes ──────────────────────────────────────────────

/** Series colors for multi-series charts, in order. Each is readable on every theme's cards. */
export const SERIES_COLORS = [
  'var(--info)',
  'var(--success)',
  'var(--warning)',
  'var(--violet)',
  'var(--danger)',
  'var(--primary)',
];

/** Change-event categories (dashboard event feed and chart annotations). */
export const EVENT_CATEGORY_COLORS = {
  deployment: 'var(--info)',
  config: 'var(--warning)',
  alert: 'var(--danger)',
  default: 'var(--violet)',
} as const;
