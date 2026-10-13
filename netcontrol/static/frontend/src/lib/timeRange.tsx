import { useCallback, useMemo, useState, type ReactNode } from 'react';

import { TimeRangeContext, type TimeRangeContextValue, type TimeRangePreset } from './timeRange-context';
import { DEFAULT_TIME_RANGE, TIME_RANGE_STORAGE_KEY, parseStoredTimeRange } from './timeRangeMap';

function readStoredRange(): TimeRangePreset {
  try {
    return parseStoredTimeRange(localStorage.getItem(TIME_RANGE_STORAGE_KEY));
  } catch {
    return DEFAULT_TIME_RANGE;
  }
}

export function TimeRangeProvider({ children }: { children: ReactNode }) {
  const [range, setRangeState] = useState<TimeRangePreset>(readStoredRange);

  const setRange = useCallback((next: TimeRangePreset) => {
    setRangeState(next);
    try {
      localStorage.setItem(TIME_RANGE_STORAGE_KEY, next);
    } catch {
      // Private mode / blocked storage: the choice just won't survive a reload.
    }
  }, []);

  const value = useMemo<TimeRangeContextValue>(() => ({ range, setRange }), [range, setRange]);

  return <TimeRangeContext.Provider value={value}>{children}</TimeRangeContext.Provider>;
}
