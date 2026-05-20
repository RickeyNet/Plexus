import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import * as echarts from 'echarts';

import { useFlowStatus, useFlowTopTalkers } from '@/api/networkTools';
import { formatBytes } from '@/pages/NetworkTools/formatting';

type Hours = 1 | 6 | 24;
type Direction = 'src' | 'dst';

const RANGES: { value: Hours; label: string }[] = [
  { value: 1, label: '1h' },
  { value: 6, label: '6h' },
  { value: 24, label: '24h' },
];

const DIRECTIONS: { value: Direction; label: string }[] = [
  { value: 'src', label: 'Source' },
  { value: 'dst', label: 'Destination' },
];

export function TopTalkersPanel() {
  const status = useFlowStatus();
  const [hours, setHours] = useState<Hours>(1);
  const [direction, setDirection] = useState<Direction>('src');
  const talkers = useFlowTopTalkers({ hours, direction, hostId: null, limit: 10 });

  const collectorOff = status.data && !status.data.enabled;

  return (
    <div className="glass-card card dashboard-overview-card">
      <div className="dashboard-overview-header">
        <h3 className="dashboard-overview-title">Top Talkers</h3>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <div className="dashboard-range-tabs" role="tablist" aria-label="Direction">
            {DIRECTIONS.map((d) => (
              <button
                key={d.value}
                role="tab"
                aria-selected={direction === d.value}
                className={`dashboard-range-tab${direction === d.value ? ' active' : ''}`}
                onClick={() => setDirection(d.value)}
              >
                {d.label}
              </button>
            ))}
          </div>
          <div className="dashboard-range-tabs" role="tablist" aria-label="Time range">
            {RANGES.map((r) => (
              <button
                key={r.value}
                role="tab"
                aria-selected={hours === r.value}
                className={`dashboard-range-tab${hours === r.value ? ' active' : ''}`}
                onClick={() => setHours(r.value)}
              >
                {r.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {status.isPending ? (
        <div className="skeleton skeleton-card" style={{ height: 260 }} />
      ) : collectorOff ? (
        <div className="dashboard-response-empty" style={{ flexDirection: 'column', gap: '0.5rem' }}>
          <p style={{ margin: 0, color: 'var(--text-muted)' }}>
            NetFlow / sFlow collector is disabled.
          </p>
          <Link to="/settings" className="dashboard-overview-link">
            Enable in Settings →
          </Link>
        </div>
      ) : talkers.isPending ? (
        <div className="skeleton skeleton-card" style={{ height: 260 }} />
      ) : talkers.error ? (
        <p style={{ color: 'var(--danger)', margin: 0 }}>
          Failed to load: {(talkers.error as Error).message}
        </p>
      ) : !talkers.data || talkers.data.length === 0 ? (
        <div className="dashboard-response-empty">
          <p style={{ margin: 0, color: 'var(--text-muted)' }}>
            No traffic recorded in this window.
          </p>
        </div>
      ) : (
        <TalkersBars rows={talkers.data} />
      )}
    </div>
  );
}

function TalkersBars({ rows }: { rows: { ip: string; total_bytes: number; flow_count: number }[] }) {
  const ref = useRef<HTMLDivElement>(null);

  // Sort ascending so the largest talker renders at the top of a horizontal
  // bar chart (echarts draws the first category at the bottom).
  const sorted = useMemo(
    () => [...rows].sort((a, b) => a.total_bytes - b.total_bytes),
    [rows],
  );

  useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current, undefined, { renderer: 'canvas' });

    chart.setOption({
      animation: false,
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'shadow' },
        formatter: (params: { name: string; value: number; data: { flows: number } }[]) => {
          const p = params[0];
          return `<strong>${p.name}</strong><br/>${formatBytes(p.value)}<br/>${p.data.flows} flows`;
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
          itemStyle: { color: '#3b82f6', borderRadius: [0, 3, 3, 0] },
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
    });

    const onResize = () => chart.resize();
    window.addEventListener('resize', onResize);
    return () => {
      window.removeEventListener('resize', onResize);
      chart.dispose();
    };
  }, [sorted]);

  return <div ref={ref} style={{ width: '100%', height: 260 }} />;
}
