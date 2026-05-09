import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';

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

interface TimeRangeContextValue extends TimeRangeState {
  setRange: (range: TimeRangePreset) => void;
  setCustomRange: (start: string, end: string) => void;
  params: TimeRangeParams;
}

const TimeRangeContext = createContext<TimeRangeContextValue | null>(null);

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

export function useTimeRange(): TimeRangeContextValue {
  const ctx = useContext(TimeRangeContext);
  if (!ctx) throw new Error('useTimeRange must be used inside <TimeRangeProvider>');
  return ctx;
}
