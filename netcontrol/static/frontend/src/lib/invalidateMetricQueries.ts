import type { QueryClient } from '@tanstack/react-query';

// Query keys touched by the global time-range bar (Dashboard, Monitoring).
const METRIC_QUERY_KEYS = [
  'metrics',
  'metrics-query',
  'interface-timeseries',
  'top-interfaces',
  'annotations',
  'flows',
  'dashboard',
  'monitoring-poll-history',
  'monitoring-polls',
  'monitoring-summary',
] as const;

export function invalidateMetricQueries(qc: QueryClient): void {
  for (const key of METRIC_QUERY_KEYS) {
    qc.invalidateQueries({ queryKey: [key] });
  }
}
