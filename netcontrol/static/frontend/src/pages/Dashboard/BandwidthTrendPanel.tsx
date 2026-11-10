import { useMemo } from 'react';

import { useTopInterfaces, type TopInterface } from '@/api/dashboard';
import { ClampedRangeHint } from '@/components/TimeRangeBar';
import { TimeSeriesChart, type TimeSeries } from '@/lib/echart';
import { SERIES_COLORS } from '@/lib/themeColors';
import { useTimeRange } from '@/lib/timeRange-context';
import { clampPreset } from '@/lib/timeRangeMap';

import { PANEL_BODY_HEIGHT, PANEL_BODY_STYLE } from './helpers';

// /api/dashboard/top-interfaces only knows 1h..7d and falls back to 6h otherwise.
const TOP_INTERFACE_RANGES = ['1h', '6h', '24h', '7d'] as const;

// Distinct line colors for up to 5 interfaces, from the theme's series palette.
const LINE_COLORS = SERIES_COLORS.slice(0, 5);

export function BandwidthTrendPanel() {
  const { range: globalRange } = useTimeRange();
  const range = clampPreset(globalRange, TOP_INTERFACE_RANGES);
  const { data, isPending, error } = useTopInterfaces({ range, limit: 5 });

  const series = useMemo<TimeSeries[]>(() => {
    const interfaces = data ?? [];
    return interfaces.map((iface, i) => ({
      name: labelFor(iface),
      color: LINE_COLORS[i % LINE_COLORS.length],
      data: iface.samples
        .filter((s) => s.ts != null)
        .map((s) => ({
          time: s.ts as string,
          // Sum in + out so each interface is one line; matches the "total
          // traffic on this port" mental model.
          value: (s.in_bps ?? 0) + (s.out_bps ?? 0),
        })),
    }));
  }, [data]);

  const hasData = series.some((s) => s.data.length > 0);

  return (
    <div className="glass-card card dashboard-overview-card">
      <div className="dashboard-overview-header">
        <h3 className="dashboard-overview-title">Busiest Interfaces</h3>
        <ClampedRangeHint requested={globalRange} shown={range} />
      </div>

      {isPending ? (
        <div className="skeleton skeleton-card" style={PANEL_BODY_STYLE} />
      ) : error ? (
        <div className="dashboard-response-empty">
          <p style={{ color: 'var(--danger)', margin: 0 }}>
            Failed to load: {(error as Error).message}
          </p>
        </div>
      ) : !hasData ? (
        <div className="dashboard-response-empty">
          <p style={{ margin: 0, color: 'var(--text-muted)' }}>
            No interface bandwidth samples yet for this range.
          </p>
        </div>
      ) : (
        <TimeSeriesChart series={series} area yAxisName="bps" height={PANEL_BODY_HEIGHT} />
      )}
    </div>
  );
}

function labelFor(iface: TopInterface): string {
  const host = iface.hostname || `host ${iface.host_id}`;
  const port = iface.if_name || `if ${iface.if_index}`;
  return `${host}: ${port}`;
}
