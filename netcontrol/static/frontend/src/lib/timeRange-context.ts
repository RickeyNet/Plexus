import { createContext, useContext } from 'react';

export type TimeRangePreset = '1h' | '6h' | '24h' | '7d' | '30d' | 'custom';

export interface TimeRangeState {
  range: TimeRangePreset;
  customStart: string | null;
  customEnd: string | null;
}

export interface TimeRangeParams {
  range: TimeRangePreset;
  start?: string;
  end?: string;
}

export interface TimeRangeContextValue extends TimeRangeState {
  setRange: (range: TimeRangePreset) => void;
  setCustomRange: (start: string, end: string) => void;
  params: TimeRangeParams;
}

export const TimeRangeContext = createContext<TimeRangeContextValue | null>(null);

export function useTimeRange(): TimeRangeContextValue {
  const ctx = useContext(TimeRangeContext);
  if (!ctx) throw new Error('useTimeRange must be used inside <TimeRangeProvider>');
  return ctx;
}
