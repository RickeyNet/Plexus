import { useEffect, useMemo, useRef } from 'react';
import { useNavigate } from 'react-router';
import { echarts } from '@/lib/echart-core';
import { observeChartResize } from '@/lib/useEChart';
import { resolveThemeVars, useThemeName } from '@/lib/themeColors';

import type { DeviceHealth } from '@/api/dashboard';

import { CountLink } from './CountLink';
import {
  DEVICE_HEALTH_FILTERS,
  type DeviceHealthFilter,
  countDeviceHealthFilters,
  countNoun,
  devicesPanelLink,
} from './dashboardLinks';
import { HEALTH_COLORS, PANEL_BODY_HEIGHT } from './helpers';

/** The "Overall Health" card: the canonical global device-health count. */
export function OverviewPanels({ devices }: { devices: DeviceHealth[] }) {
  return (
    <div className="glass-card card dashboard-overview-card">
      <h3 className="dashboard-overview-title">Overall Health</h3>
      <HealthDonut devices={devices} />
    </div>
  );
}

interface Slice {
  filter: DeviceHealthFilter;
  name: string;
  value: number;
  color: string;
}

function HealthDonut({ devices }: { devices: DeviceHealth[] }) {
  const ref = useRef<HTMLDivElement>(null);
  const theme = useThemeName();
  const navigate = useNavigate();

  // Critical and down share one slice, matching the four buckets the other
  // dashboard panels show.
  const slices = useMemo<Slice[]>(() => {
    const value = countDeviceHealthFilters(devices);
    // Healthy first, as the donut has always drawn them.
    const order: DeviceHealthFilter[] = ['healthy', 'warning', 'critical', 'unknown'];
    return order.map((filter) => ({
      filter,
      name: DEVICE_HEALTH_FILTERS.find((f) => f.key === filter)!.label,
      value: value[filter],
      color: HEALTH_COLORS[filter],
    }));
  }, [devices]);

  const total = devices.length;

  useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current, undefined, { renderer: 'canvas' });
    const hasData = slices.some((s) => s.value > 0);

    // The legend is the list beside the chart (links, keyboard reachable),
    // so the chart draws none and a click never hides a slice.
    chart.setOption(resolveThemeVars({
      animation: false,
      tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
      series: [
        {
          type: 'pie',
          radius: ['58%', '78%'],
          center: ['50%', '50%'],
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
          data: hasData
            ? slices.map((s) => ({ name: s.name, value: s.value, itemStyle: { color: s.color } }))
            : [{ name: 'No data', value: 1, itemStyle: { color: 'var(--border)' } }],
          silent: !hasData,
        },
      ],
    }));

    // A slice opens the Devices panel filtered to its bucket, like its legend entry.
    chart.on('click', (params) => {
      const slice = hasData ? slices[params.dataIndex] : undefined;
      if (slice && slice.value > 0) void navigate(devicesPanelLink(slice.filter));
    });

    const stopObserving = observeChartResize(chart, ref.current);
    return () => {
      stopObserving();
      chart.dispose();
    };
  }, [slices, total, theme, navigate]);

  return (
    <div className="dashboard-donut" style={{ height: PANEL_BODY_HEIGHT }}>
      <div ref={ref} className="dashboard-donut-chart" />
      <ul className="dashboard-donut-legend">
        {slices.map((s) => (
          <li key={s.filter}>
            <span className="dashboard-donut-dot" style={{ background: s.color }} aria-hidden="true" />
            <CountLink
              to={s.value > 0 ? devicesPanelLink(s.filter) : null}
              label={`Show ${countNoun(s.value, `${s.name} device`, `${s.name} devices`)}`}
              className="dashboard-donut-entry"
            >
              <span>{s.name}</span>
              <strong>{s.value}</strong>
            </CountLink>
          </li>
        ))}
      </ul>
    </div>
  );
}

function formatCount(n: number): string {
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  return String(n);
}
