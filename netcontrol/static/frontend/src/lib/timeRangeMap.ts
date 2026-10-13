import { TIME_RANGE_PRESETS, type TimeRangePreset } from './timeRange-context';

export const DEFAULT_TIME_RANGE: TimeRangePreset = '6h';
export const TIME_RANGE_STORAGE_KEY = 'plexus.timeRange';

const PRESET_HOURS: Record<TimeRangePreset, number> = {
  '1h': 1,
  '6h': 6,
  '24h': 24,
  '7d': 168,
  '30d': 720,
};

export function isTimeRangePreset(value: unknown): value is TimeRangePreset {
  return typeof value === 'string' && (TIME_RANGE_PRESETS as readonly string[]).includes(value);
}

export function toHours(preset: TimeRangePreset): number {
  return PRESET_HOURS[preset];
}

/** Whole days covering the preset, never less than 1 (for `days=` endpoints). */
export function toDays(preset: TimeRangePreset): number {
  return Math.max(1, Math.ceil(PRESET_HOURS[preset] / 24));
}

/**
 * Largest allowed preset that does not exceed `preset`; the smallest allowed
 * one when every allowed preset is longer. For endpoints that reject or
 * silently ignore the longer windows.
 */
export function clampPreset<T extends TimeRangePreset>(preset: TimeRangePreset, allowed: readonly T[]): T {
  if (allowed.length === 0) throw new Error('clampPreset: allowed must not be empty');
  const sorted = [...allowed].sort((a, b) => PRESET_HOURS[a] - PRESET_HOURS[b]);
  let best = sorted[0];
  for (const p of sorted) {
    if (PRESET_HOURS[p] <= PRESET_HOURS[preset]) best = p;
  }
  return best;
}

export function parseStoredTimeRange(raw: string | null): TimeRangePreset {
  return isTimeRangePreset(raw) ? raw : DEFAULT_TIME_RANGE;
}
