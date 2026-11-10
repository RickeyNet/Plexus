import { useEffect, useRef } from 'react';

import { chartTooltipFormatter, formatBpsTick } from './chartFormat';
import { EVENT_CATEGORY_COLORS, SERIES_COLORS, resolveThemeVars, useThemeName } from './themeColors';
import { useEChart } from './useEChart';

export interface TimeSeriesPoint {
  time: string;
  value: number;
}

export interface TimeSeries {
  name: string;
  data: TimeSeriesPoint[];
  color?: string;
  /** Dashed line, for projected or estimated values. */
  dashed?: boolean;
}

/** A horizontal reference line at one y value (a capacity threshold, an SLA target). */
export interface ChartThreshold {
  value: number;
  label?: string;
}

export interface ChartAnnotation {
  timestamp: string;
  category?: string;
  title?: string;
  action?: string;
}

const ANNOTATION_COLORS: Record<string, string> = EVENT_CATEGORY_COLORS;

interface TimeSeriesChartProps {
  series: TimeSeries[];
  area?: boolean;
  yAxisName?: string;
  /** Suffix of each tooltip value ("%", " ms"). */
  unit?: string;
  yMin?: number;
  yMax?: number;
  height?: number | string;
  annotations?: ChartAnnotation[];
  threshold?: ChartThreshold;
}

// Pixel height when the caller passes none. A string such as '100%' lets the
// chart fill a container that has its own height (custom dashboard panels).
const DEFAULT_HEIGHT = 240;

// Options are written with theme tokens and resolved to concrete colors by
// resolveThemeVars() just before setOption: the canvas renderer ignores a
// color it cannot parse, and it cannot parse var(). Each chart re-applies its
// option when the theme changes (useThemeName in the effect dependencies).
const TEXT_COLOR = 'var(--text)';
const AXIS_COLOR = 'var(--text-muted)';
const SPLIT_COLOR = 'var(--border)';

export function TimeSeriesChart({
  series,
  area,
  yAxisName,
  unit,
  yMin,
  yMax,
  height = DEFAULT_HEIGHT,
  annotations,
  threshold,
}: TimeSeriesChartProps) {
  const ref = useRef<HTMLDivElement>(null);
  // One instance per mount, resized with its container, disposed on unmount.
  const chartRef = useEChart(ref);
  const theme = useThemeName();

  // Data effect: reuse the retained instance via setOption (no re-init).
  useEffect(() => {
    const chart = chartRef.current;
    if (!chart) return;

    const isBpsAxis = yAxisName === 'bps';

    // Legacy parity: overlay deployment/config/alert markers on series[0]
    // as a silent dashed markLine (PlexusChart.addAnnotations).
    const markLineData: Record<string, unknown>[] = (annotations ?? [])
      .filter((e) => e.timestamp)
      .map((e) => {
        const color = ANNOTATION_COLORS[e.category ?? 'default'] ?? ANNOTATION_COLORS.default;
        return {
          xAxis: new Date(e.timestamp).getTime(),
          label: {
            formatter: e.title || e.action || '',
            position: 'start' as const,
            fontSize: 9,
            color,
          },
          lineStyle: { color, type: 'dashed' as const, width: 1 },
        };
      });
    if (threshold) {
      markLineData.push({
        yAxis: threshold.value,
        label: {
          formatter: threshold.label ?? '',
          position: 'insideEndTop' as const,
          fontSize: 10,
          color: 'var(--danger)',
        },
        lineStyle: { color: 'var(--danger)', type: 'dashed' as const, width: 1 },
      });
    }

    const formatValue = chartTooltipFormatter(isBpsAxis ? 'bps' : 'number');
    const valueFormatter = unit
      ? (value: unknown) => {
          const text = formatValue(value);
          return text === '-' ? text : text + unit;
        }
      : formatValue;

    chart.setOption(
      resolveThemeVars({
        animation: false,
        color: SERIES_COLORS,
        tooltip: {
          trigger: 'axis',
          axisPointer: { type: 'cross' },
          valueFormatter,
        },
        // Scroll legend: one line with a pager, so long or many series names
        // never wrap down over the plot.
        legend:
          series.length > 1
            ? {
                type: 'scroll',
                data: series.map((s) => s.name),
                left: 8,
                right: 8,
                textStyle: { color: TEXT_COLOR },
                pageIconColor: TEXT_COLOR,
                pageIconInactiveColor: SPLIT_COLOR,
                pageTextStyle: { color: AXIS_COLOR },
              }
            : undefined,
        grid: {
          left: 50,
          right: 16,
          top: series.length > 1 ? 32 : 16,
          bottom: 30,
          containLabel: true,
        },
        xAxis: {
          type: 'time',
          axisLabel: { color: AXIS_COLOR },
          axisLine: { lineStyle: { color: SPLIT_COLOR } },
          splitLine: { show: false },
        },
        yAxis: {
          type: 'value',
          name: yAxisName,
          nameTextStyle: { color: AXIS_COLOR },
          min: yMin,
          max: yMax,
          axisLabel: {
            color: AXIS_COLOR,
            formatter: isBpsAxis ? formatBpsTick : undefined,
          },
          splitLine: { lineStyle: { color: SPLIT_COLOR } },
        },
        series: series.map((s, i) => ({
          name: s.name,
          type: 'line',
          showSymbol: false,
          smooth: false,
          sampling: 'lttb',
          itemStyle: s.color ? { color: s.color } : undefined,
          lineStyle: { width: 1.5, type: s.dashed ? ('dashed' as const) : ('solid' as const) },
          areaStyle: area ? { opacity: 0.2 } : undefined,
          data: s.data.map((p) => [p.time, p.value]),
          markLine:
            i === 0 && markLineData.length
              ? { silent: true, symbol: 'none', data: markLineData }
              : undefined,
        })),
      }),
      // Fully replace: series/legend count varies with input, so a merge
      // would leave stale series/legend entries behind.
      { notMerge: true },
    );
  }, [chartRef, series, area, yAxisName, unit, yMin, yMax, annotations, threshold, theme]);

  return <div ref={ref} style={{ width: '100%', height }} />;
}

interface GaugeChartProps {
  value: number;
  title?: string;
  min?: number;
  max?: number;
  height?: number | string;
}

export function GaugeChart({ value, title, min = 0, max = 100, height = DEFAULT_HEIGHT }: GaugeChartProps) {
  const ref = useRef<HTMLDivElement>(null);
  // One instance per mount, resized with its container, disposed on unmount.
  const chartRef = useEChart(ref);
  const theme = useThemeName();

  // Data effect: reuse the retained instance via setOption (no re-init).
  useEffect(() => {
    const chart = chartRef.current;
    if (!chart) return;

    chart.setOption(
      resolveThemeVars({
        animation: false,
        color: SERIES_COLORS,
        series: [
          {
            type: 'gauge',
            min,
            max,
            progress: { show: true, width: 14 },
            axisLine: { lineStyle: { width: 14, color: [[1, SPLIT_COLOR]] } },
            pointer: { show: false },
            axisTick: { show: false },
            splitLine: { show: false },
            axisLabel: { show: false },
            detail: {
              valueAnimation: false,
              formatter: '{value}',
              fontSize: 22,
              color: TEXT_COLOR,
              offsetCenter: [0, '10%'],
            },
            title: {
              show: !!title,
              offsetCenter: [0, '70%'],
              color: AXIS_COLOR,
              fontSize: 12,
            },
            data: [{ value: Math.round(value * 10) / 10, name: title ?? '' }],
          },
        ],
      }),
      { notMerge: true },
    );
  }, [chartRef, value, title, min, max, theme]);

  return <div ref={ref} style={{ width: '100%', height }} />;
}

interface HeatmapChartProps {
  xLabels: string[];
  yLabels: string[];
  data: [number, number, number][];
  height?: number | string;
}

export function HeatmapChart({ xLabels, yLabels, data, height = DEFAULT_HEIGHT }: HeatmapChartProps) {
  const ref = useRef<HTMLDivElement>(null);
  // One instance per mount, resized with its container, disposed on unmount.
  const chartRef = useEChart(ref);
  const theme = useThemeName();

  // Data effect: reuse the retained instance via setOption (no re-init).
  useEffect(() => {
    const chart = chartRef.current;
    if (!chart) return;

    const values = data.map((d) => d[2]);
    const dataMin = values.length ? Math.min(...values) : 0;
    const dataMax = values.length ? Math.max(...values) : 1;

    chart.setOption(
      resolveThemeVars({
        animation: false,
        color: SERIES_COLORS,
        tooltip: { position: 'top' },
        grid: { left: 60, right: 16, top: 24, bottom: 60, containLabel: true },
        xAxis: {
          type: 'category',
          data: xLabels,
          splitArea: { show: true },
          axisLabel: { color: AXIS_COLOR, rotate: 45 },
          axisLine: { lineStyle: { color: SPLIT_COLOR } },
        },
        yAxis: {
          type: 'category',
          data: yLabels,
          splitArea: { show: true },
          axisLabel: { color: AXIS_COLOR },
          axisLine: { lineStyle: { color: SPLIT_COLOR } },
        },
        visualMap: {
          min: dataMin,
          max: dataMax,
          calculable: true,
          orient: 'horizontal',
          left: 'center',
          bottom: 0,
          textStyle: { color: AXIS_COLOR },
          inRange: { color: ['var(--border)', 'var(--info)', 'var(--warning)', 'var(--danger)'] },
        },
        series: [
          {
            name: 'value',
            type: 'heatmap',
            data,
            label: { show: false },
          },
        ],
      }),
      { notMerge: true },
    );
  }, [chartRef, xLabels, yLabels, data, theme]);

  return <div ref={ref} style={{ width: '100%', height }} />;
}

interface BarChartProps {
  categories: string[];
  values: number[];
  rotateLabels?: number;
  height?: number | string;
}

export function BarChart({
  categories,
  values,
  rotateLabels = 0,
  height = DEFAULT_HEIGHT,
}: BarChartProps) {
  const ref = useRef<HTMLDivElement>(null);
  // One instance per mount, resized with its container, disposed on unmount.
  const chartRef = useEChart(ref);
  const theme = useThemeName();

  // Data effect: reuse the retained instance via setOption (no re-init).
  useEffect(() => {
    const chart = chartRef.current;
    if (!chart) return;

    chart.setOption(
      resolveThemeVars({
        animation: false,
        color: SERIES_COLORS,
        tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
        grid: { left: 40, right: 16, top: 16, bottom: rotateLabels ? 60 : 30, containLabel: true },
        xAxis: {
          type: 'category',
          data: categories,
          axisLabel: {
            color: AXIS_COLOR,
            rotate: rotateLabels,
            interval: 0,
          },
          axisLine: { lineStyle: { color: SPLIT_COLOR } },
        },
        yAxis: {
          type: 'value',
          axisLabel: { color: AXIS_COLOR },
          splitLine: { lineStyle: { color: SPLIT_COLOR } },
        },
        series: [
          {
            type: 'bar',
            data: values,
            itemStyle: { color: 'var(--info)' },
          },
        ],
      }),
      { notMerge: true },
    );
  }, [chartRef, categories, values, rotateLabels, theme]);

  return <div ref={ref} style={{ width: '100%', height }} />;
}
