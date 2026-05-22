import { useCallback, useMemo, useState, type ReactNode } from 'react';
import {
  TimeRangeContext,
  type TimeRangeContextValue,
  type TimeRangeParams,
  type TimeRangePreset,
  type TimeRangeState,
} from './timeRange-context';

export function TimeRangeProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<TimeRangeState>({
    range: '6h',
    customStart: null,
    customEnd: null,
  });

  const setRange = useCallback((range: TimeRangePreset) => {
    setState((prev) => ({ ...prev, range }));
  }, []);

  const setCustomRange = useCallback((start: string, end: string) => {
    setState({ range: 'custom', customStart: start, customEnd: end });
  }, []);

  const params = useMemo<TimeRangeParams>(() => {
    if (state.range === 'custom' && state.customStart && state.customEnd) {
      return { range: 'custom', start: state.customStart, end: state.customEnd };
    }
    return { range: state.range };
  }, [state]);

  const value = useMemo<TimeRangeContextValue>(
    () => ({ ...state, setRange, setCustomRange, params }),
    [state, setRange, setCustomRange, params],
  );

  return <TimeRangeContext.Provider value={value}>{children}</TimeRangeContext.Provider>;
}
