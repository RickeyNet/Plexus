import { useEffect, useMemo, useRef } from 'react';
import { echarts } from '@/lib/echart-core';

import type { DeviceHealth } from '@/api/dashboard';

import { classifyDeviceHealth, type HealthStatus } from './helpers';

const HEALTH_COLORS: Record<HealthStatus, string> = {
  healthy: '#4caf50',
  warning: '#ff9800',
  critical: '#f44336',
  down: '#b71c1c',
  unknown: '#9e9e9e',
};

const HEALTH_LABELS: Record<HealthStatus, string> = {
  healthy: 'Good',
  warning: 'Moderate',
  critical: 'Bad',
  down: 'Down',
  unknown: 'Unknown',
};

export function OverviewPanels({ devices }: { devices: DeviceHealth[] }) {
  return (
    <div className="dashboard-overview-grid">
      <div className="glass-card card dashboard-overview-card">
        <h3 className="dashboard-overview-title">Overall Health</h3>
        <HealthDonut devices={devices} />
      </div>
    </div>
  );
}

function HealthDonut({ devices }: { devices: DeviceHealth[] }) {
  const ref = useRef<HTMLDivElement>(null);

  const buckets = useMemo(() => {
    const counts: Record<HealthStatus, number> = {
      healthy: 0,
      warning: 0,
      critical: 0,
      down: 0,
      unknown: 0,
    };
    for (const d of devices) counts[classifyDeviceHealth(d)]++;
    return counts;
  }, [devices]);

  const total = devices.length;

  useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current, undefined, { renderer: 'canvas' });

    // Merge critical + down into one "Bad" slice, matching the SolarWinds
    // four-bucket layout (Good / Moderate / Bad / Unknown).
    const badCount = buckets.critical + buckets.down;
    const slices = [
      { name: HEALTH_LABELS.healthy, value: buckets.healthy, itemStyle: { color: HEALTH_COLORS.healthy } },
      { name: HEALTH_LABELS.warning, value: buckets.warning, itemStyle: { color: HEALTH_COLORS.warning } },
      { name: HEALTH_LABELS.critical, value: badCount, itemStyle: { color: HEALTH_COLORS.critical } },
      { name: HEALTH_LABELS.unknown, value: buckets.unknown, itemStyle: { color: HEALTH_COLORS.unknown } },
    ];
    const hasData = slices.some((s) => s.value > 0);

    chart.setOption({
      animation: false,
      tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
      legend: {
        orient: 'vertical',
        right: 8,
        top: 'center',
        textStyle: { color: 'var(--text)' },
        formatter: (name: string) => {
          const slice = slices.find((s) => s.name === name);
          return `${name}  ${slice ? slice.value : 0}`;
        },
      },
      series: [
        {
          type: 'pie',
          radius: ['58%', '78%'],
          center: ['35%', '50%'],
          avoidLabelOverlap: false,
          label: {
            show: true,
            position: 'center',
            formatter: () => (hasData ? `{val|${formatCount(total)}}\n{lbl|Devices}` : '{lbl|No data}'),
            rich: {
              val: { fontSize: 28, fontWeight: 600, color: 'var(--text)', lineHeight: 32 },
              lbl: { fontSize: 12, color: 'var(--text-muted)' },
            },
          },
          labelLine: { show: false },
          data: hasData ? slices : [{ name: 'No data', value: 1, itemStyle: { color: 'var(--border)' } }],
          silent: !hasData,
        },
      ],
    });

    const onResize = () => chart.resize();
    window.addEventListener('resize', onResize);
    return () => {
      window.removeEventListener('resize', onResize);
      chart.dispose();
    };
  }, [buckets, total]);

  return <div ref={ref} style={{ width: '100%', height: 240 }} />;
}

function formatCount(n: number): string {
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  return String(n);
}
