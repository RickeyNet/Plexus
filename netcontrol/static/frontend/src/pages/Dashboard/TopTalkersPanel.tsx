import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router';
import { echarts } from '@/lib/echart-core';
import { observeChartResize } from '@/lib/useEChart';
import { resolveThemeVars, useThemeName } from '@/lib/themeColors';

import { FLOW_RANGES, useFlowStatus, useFlowTopTalkers } from '@/api/networkTools';
import { SegmentedControl } from '@/components/SegmentedControl';
import { ClampedRangeHint } from '@/components/TimeRangeBar';
import { useTimeRange } from '@/lib/timeRange-context';
import { clampPreset, toHours } from '@/lib/timeRangeMap';
import { formatBytes } from '@/pages/NetworkTools/formatting';

import { PANEL_BODY_HEIGHT, PANEL_BODY_STYLE } from './helpers';
import { PanelEmpty, PanelError, PanelRangeEmpty } from './PanelStates';
import { SETUP_LINKS } from './setupGuide';

type Direction = 'src' | 'dst';

const DIRECTIONS: { key: Direction; label: string }[] = [
  { key: 'src', label: 'Source' },
  { key: 'dst', label: 'Destination' },
];

export function TopTalkersPanel() {
  const status = useFlowStatus();
  const { range } = useTimeRange();
  const flowRange = clampPreset(range, FLOW_RANGES);
  const hours = toHours(flowRange);
  const [direction, setDirection] = useState<Direction>('src');
  const talkers = useFlowTopTalkers({ hours, direction, hostId: null, limit: 10 });

  const collectorOff = status.data && !status.data.enabled;

  return (
    <div className="glass-card card dashboard-overview-card">
      <div className="dashboard-overview-header">
        <h3 className="dashboard-overview-title">Top Talkers</h3>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <ClampedRangeHint requested={range} shown={flowRange} />
          <SegmentedControl
            options={DIRECTIONS}
            value={direction}
            onChange={setDirection}
            size="xs"
            aria-label="Direction"
          />
        </div>
      </div>

      {status.isPending ? (
        <div className="skeleton skeleton-card" style={PANEL_BODY_STYLE} />
      ) : collectorOff ? (
        <PanelEmpty
          message="The NetFlow / sFlow collector is off"
          description="Top talkers are read from the flow records it receives."
          action={
            <Link to={SETUP_LINKS.netflow} className="btn btn-sm btn-secondary">
              Turn it on in Settings
            </Link>
          }
        />
      ) : talkers.isPending ? (
        <div className="skeleton skeleton-card" style={PANEL_BODY_STYLE} />
      ) : talkers.error ? (
        <PanelError what="top talkers" query={talkers} />
      ) : !talkers.data || talkers.data.length === 0 ? (
        <PanelRangeEmpty
          what="traffic recorded"
          shown={flowRange}
          allowed={FLOW_RANGES}
          hint="The collector is on but has received no flow records. Check that devices export NetFlow or sFlow to this server."
        />
      ) : (
        <TalkersBars rows={talkers.data} />
      )}
    </div>
  );
}

function TalkersBars({ rows }: { rows: { ip: string; total_bytes: number; flow_count: number }[] }) {
  const ref = useRef<HTMLDivElement>(null);
  const theme = useThemeName();

  // Sort ascending so the largest talker renders at the top of a horizontal
  // bar chart (echarts draws the first category at the bottom).
  const sorted = useMemo(
    () => [...rows].sort((a, b) => a.total_bytes - b.total_bytes),
    [rows],
  );

  useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current, undefined, { renderer: 'canvas' });

    chart.setOption(resolveThemeVars({
      animation: false,
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'shadow' },
        formatter: (params: { name: string; value: number; data: { flows: number } }[]) => {
          const p = params[0];
          // ECharts renders tooltip HTML via innerHTML, and p.name is the
          // flow "talker" IP sourced from ingested NetFlow/sFlow data (not
          // trusted). Escape it to prevent DOM-XSS. The numeric fields are safe.
          const name = String(p.name).replace(/[&<>"']/g, (c) =>
            ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string,
          );
          return `<strong>${name}</strong><br/>${formatBytes(p.value)}<br/>${p.data.flows} flows`;
        },
      },
      grid: { left: 8, right: 60, top: 8, bottom: 24, containLabel: true },
      xAxis: {
        type: 'value',
        axisLabel: {
          color: 'var(--text-muted)',
          formatter: (v: number) => formatBytes(v),
        },
        splitLine: { lineStyle: { color: 'var(--border)' } },
      },
      yAxis: {
        type: 'category',
        data: sorted.map((r) => r.ip),
        axisLabel: { color: 'var(--text-muted)', fontSize: 11 },
        axisLine: { lineStyle: { color: 'var(--border)' } },
      },
      series: [
        {
          type: 'bar',
          data: sorted.map((r) => ({
            value: r.total_bytes,
            flows: r.flow_count,
          })),
          itemStyle: { color: 'var(--info)', borderRadius: [0, 3, 3, 0] },
          label: {
            show: true,
            position: 'right',
            color: 'var(--text)',
            fontSize: 11,
            formatter: (p: { value: number }) => formatBytes(p.value),
          },
          barMaxWidth: 18,
        },
      ],
    }));

    const stopObserving = observeChartResize(chart, ref.current);
    return () => {
      stopObserving();
      chart.dispose();
    };
  }, [sorted, theme]);

  return <div ref={ref} style={{ width: '100%', height: PANEL_BODY_HEIGHT }} />;
}
