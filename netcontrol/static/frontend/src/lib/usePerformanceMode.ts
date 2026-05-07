import { useCallback, useEffect, useState } from 'react';

const PERF_KEY = 'plexus_performance_mode';

// Mirrors the legacy applyPerformanceMode/initPerformanceMode flow. The CSS
// already keys off `body.reduced-motion`, so toggling that class is enough —
// the starfield and CSS animations both honor it.
function readInitial(): boolean {
  const saved = localStorage.getItem(PERF_KEY);
  if (saved !== null) return saved === '1';
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

export function usePerformanceMode(): { enabled: boolean; toggle: () => void } {
  const [enabled, setEnabled] = useState<boolean>(readInitial);

  useEffect(() => {
    document.body.classList.toggle('reduced-motion', enabled);
    localStorage.setItem(PERF_KEY, enabled ? '1' : '0');
  }, [enabled]);

  const toggle = useCallback(() => setEnabled((v) => !v), []);
  return { enabled, toggle };
}
