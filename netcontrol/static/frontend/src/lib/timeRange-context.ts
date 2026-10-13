import { createContext, useContext } from 'react';

export const TIME_RANGE_PRESETS = ['1h', '6h', '24h', '7d', '30d'] as const;

export type TimeRangePreset = (typeof TIME_RANGE_PRESETS)[number];

export interface TimeRangeContextValue {
  range: TimeRangePreset;
  setRange: (range: TimeRangePreset) => void;
}

export const TimeRangeContext = createContext<TimeRangeContextValue | null>(null);

export function useTimeRange(): TimeRangeContextValue {
  const ctx = useContext(TimeRangeContext);
  if (!ctx) throw new Error('useTimeRange must be used inside <TimeRangeProvider>');
  return ctx;
}
