import { useEffect, useMemo, useRef } from 'react';
import { echarts } from '@/lib/echart-core';
import { observeChartResize } from '@/lib/useEChart';
import { resolveThemeVars, useThemeName } from '@/lib/themeColors';

import type { DeviceHealth } from '@/api/dashboard';

import {
  CRITICAL_DOWN_LABEL,
  HEALTH_COLORS,
  HEALTH_LABELS,
  PANEL_BODY_HEIGHT,
  countDeviceHealth,
} from './helpers';

/** The "Overall Health" card: the canonical global device-health count. */
export function OverviewPanels({ devices }: { devices: DeviceHealth[] }) {
  return (
    <div className="glass-card card dashboard-overview-card">
      <h3 className="dashboard-overview-title">Overall Health</h3>
      <HealthDonut devices={devices} />
    </div>
  );
}

function HealthDonut({ devices }: { devices: DeviceHealth[] }) {
  const ref = useRef<HTMLDivElement>(null);
  const theme = useThemeName();

  const buckets = useMemo(() => countDeviceHealth(devices), [devices]);

  const total = devices.length;

  useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current, undefined, { renderer: 'canvas' });

    // Merge critical + down into one slice, matching the four buckets the
    // other dashboard panels show.
    const badCount = buckets.critical + buckets.down;
    const slices = [
      { name: HEALTH_LABELS.healthy, value: buckets.healthy, itemStyle: { color: HEALTH_COLORS.healthy } },
      { name: HEALTH_LABELS.warning, value: buckets.warning, itemStyle: { color: HEALTH_COLORS.warning } },
      { name: CRITICAL_DOWN_LABEL, value: badCount, itemStyle: { color: HEALTH_COLORS.critical } },
      { name: HEALTH_LABELS.unknown, value: buckets.unknown, itemStyle: { color: HEALTH_COLORS.unknown } },
    ];
    const hasData = slices.some((s) => s.value > 0);

    chart.setOption(resolveThemeVars({
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
    }));

    const stopObserving = observeChartResize(chart, ref.current);
    return () => {
      stopObserving();
      chart.dispose();
    };
  }, [buckets, total, theme]);

  return <div ref={ref} style={{ width: '100%', height: PANEL_BODY_HEIGHT }} />;
}

function formatCount(n: number): string {
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  return String(n);
}
