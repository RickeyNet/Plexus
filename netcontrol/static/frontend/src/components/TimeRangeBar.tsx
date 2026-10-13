import { useQueryClient } from '@tanstack/react-query';

import { invalidateMetricQueries } from '@/lib/invalidateMetricQueries';
import { TIME_RANGE_PRESETS, useTimeRange, type TimeRangePreset } from '@/lib/timeRange-context';

export function TimeRangeBar() {
  const { range, setRange } = useTimeRange();
  const qc = useQueryClient();

  return (
    <div className="time-range-bar">
      <div className="time-range-presets" role="group" aria-label="Time range">
        {TIME_RANGE_PRESETS.map((p) => (
          <button
            key={p}
            type="button"
            className={`time-range-btn${range === p ? ' active' : ''}`}
            aria-pressed={range === p}
            onClick={() => setRange(p)}
          >
            {p}
          </button>
        ))}
      </div>
      <button
        type="button"
        className="btn btn-sm btn-secondary time-range-refresh"
        onClick={() => invalidateMetricQueries(qc)}
        title="Refresh"
        aria-label="Refresh"
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="23 4 23 10 17 10" />
          <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
        </svg>
      </button>
    </div>
  );
}

/** Muted note shown when a panel can't honor the global range and clamps it. */
export function ClampedRangeHint({ requested, shown }: { requested: TimeRangePreset; shown: TimeRangePreset }) {
  if (requested === shown) return null;
  return (
    <span
      className="text-muted"
      style={{ fontSize: '0.8rem', whiteSpace: 'nowrap' }}
      title={`This view supports up to ${shown}`}
    >
      (showing {shown})
    </span>
  );
}
