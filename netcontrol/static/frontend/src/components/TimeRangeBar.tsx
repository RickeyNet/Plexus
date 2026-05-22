import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';

import { useTimeRange, type TimeRangePreset } from '@/lib/timeRange-context';

const PRESETS: TimeRangePreset[] = ['1h', '6h', '24h', '7d', '30d', 'custom'];
const PRESET_LABELS: Record<TimeRangePreset, string> = {
  '1h': '1h',
  '6h': '6h',
  '24h': '24h',
  '7d': '7d',
  '30d': '30d',
  custom: 'Custom',
};

export function TimeRangeBar() {
  const { range, customStart, customEnd, setRange, setCustomRange } = useTimeRange();
  const qc = useQueryClient();
  const [start, setStart] = useState(customStart ?? '');
  const [end, setEnd] = useState(customEnd ?? '');

  function applyCustom() {
    if (!start || !end) {
      alert('Please select both start and end times');
      return;
    }
    setCustomRange(start, end);
  }

  function refresh() {
    qc.invalidateQueries();
  }

  return (
    <div className="time-range-bar">
      <div className="time-range-presets">
        {PRESETS.map((p) => (
          <button
            key={p}
            type="button"
            className={`time-range-btn${range === p ? ' active' : ''}`}
            onClick={() => setRange(p)}
          >
            {PRESET_LABELS[p]}
          </button>
        ))}
      </div>
      {range === 'custom' && (
        <div className="time-range-custom">
          <input
            type="datetime-local"
            className="form-input"
            value={start}
            onChange={(e) => setStart(e.target.value)}
          />
          <span style={{ color: 'var(--text-muted)' }}>to</span>
          <input
            type="datetime-local"
            className="form-input"
            value={end}
            onChange={(e) => setEnd(e.target.value)}
          />
          <button type="button" className="btn btn-sm btn-primary" onClick={applyCustom}>
            Apply
          </button>
        </div>
      )}
      <button
        type="button"
        className="btn btn-sm btn-secondary time-range-refresh"
        onClick={refresh}
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
