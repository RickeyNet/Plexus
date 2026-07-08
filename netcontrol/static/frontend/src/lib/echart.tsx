import { useEffect, useRef } from 'react';
import { echarts, type ECharts } from './echart-core';

export interface TimeSeriesPoint {
  time: string;
  value: number;
}

export interface TimeSeries {
  name: string;
  data: TimeSeriesPoint[];
  color?: string;
}

export interface ChartAnnotation {
  timestamp: string;
  category?: string;
  title?: string;
  action?: string;
}

// Matches the legacy PlexusChart.addAnnotations() palette (app.js).
const ANNOTATION_COLORS: Record<string, string> = {
  deployment: '#3b82f6',
  config: '#f59e0b',
  alert: '#ef4444',
  default: '#8b5cf6',
};

interface TimeSeriesChartProps {
  series: TimeSeries[];
  area?: boolean;
  yAxisName?: string;
  yMin?: number;
  yMax?: number;
  height?: number;
  annotations?: ChartAnnotation[];
}

const DEFAULT_HEIGHT = 240;

const TEXT_COLOR = 'var(--text)';
const AXIS_COLOR = 'var(--text-muted)';
const SPLIT_COLOR = 'var(--border)';

function formatBpsTick(v: number): string {
  const abs = Math.abs(v);
  if (abs >= 1e12) return (v / 1e12).toFixed(1) + 'T';
  if (abs >= 1e9) return (v / 1e9).toFixed(1) + 'G';
  if (abs >= 1e6) return (v / 1e6).toFixed(1) + 'M';
  if (abs >= 1e3) return (v / 1e3).toFixed(1) + 'k';
  return String(v);
}

export function TimeSeriesChart({
  series,
  area,
  yAxisName,
  yMin,
  yMax,
  height = DEFAULT_HEIGHT,
  annotations,
}: TimeSeriesChartProps) {
  const ref = useRef<HTMLDivElement>(null);
  const chartRef = useRef<ECharts | null>(null);

  // Mount-only: create the instance once, wire resize, dispose on unmount.
  useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current, undefined, { renderer: 'canvas' });
    chartRef.current = chart;

    const onResize = () => chart.resize();
    window.addEventListener('resize', onResize);
    return () => {
      window.removeEventListener('resize', onResize);
      chart.dispose();
      chartRef.current = null;
    };
  }, []);

  // Data effect: reuse the retained instance via setOption (no re-init).
  useEffect(() => {
    const chart = chartRef.current;
    if (!chart) return;

    const isBpsAxis = yAxisName === 'bps';

    // Legacy parity: overlay deployment/config/alert markers on series[0]
    // as a silent dashed markLine (PlexusChart.addAnnotations).
    const markLineData = (annotations ?? [])
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

    chart.setOption(
      {
        animation: false,
        tooltip: {
          trigger: 'axis',
          axisPointer: { type: 'cross' },
        },
        legend:
          series.length > 1
            ? { data: series.map((s) => s.name), textStyle: { color: TEXT_COLOR } }
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
          lineStyle: { width: 1.5 },
          areaStyle: area ? { opacity: 0.2 } : undefined,
          data: s.data.map((p) => [p.time, p.value]),
          markLine:
            i === 0 && markLineData.length
              ? { silent: true, symbol: 'none', data: markLineData }
              : undefined,
        })),
      },
      // Fully replace: series/legend count varies with input, so a merge
      // would leave stale series/legend entries behind.
      { notMerge: true },
    );
  }, [series, area, yAxisName, yMin, yMax, annotations]);

  return <div ref={ref} style={{ width: '100%', height }} />;
}

interface GaugeChartProps {
  value: number;
  title?: string;
  min?: number;
  max?: number;
  height?: number;
}

export function GaugeChart({ value, title, min = 0, max = 100, height = DEFAULT_HEIGHT }: GaugeChartProps) {
  const ref = useRef<HTMLDivElement>(null);
  const chartRef = useRef<ECharts | null>(null);

  // Mount-only: create the instance once, wire resize, dispose on unmount.
  useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current, undefined, { renderer: 'canvas' });
    chartRef.current = chart;

    const onResize = () => chart.resize();
    window.addEventListener('resize', onResize);
    return () => {
      window.removeEventListener('resize', onResize);
      chart.dispose();
      chartRef.current = null;
    };
  }, []);

  // Data effect: reuse the retained instance via setOption (no re-init).
  useEffect(() => {
    const chart = chartRef.current;
    if (!chart) return;

    chart.setOption(
      {
        animation: false,
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
      },
      { notMerge: true },
    );
  }, [value, title, min, max]);

  return <div ref={ref} style={{ width: '100%', height }} />;
}

interface HeatmapChartProps {
  xLabels: string[];
  yLabels: string[];
  data: [number, number, number][];
  height?: number;
}

export function HeatmapChart({ xLabels, yLabels, data, height = DEFAULT_HEIGHT }: HeatmapChartProps) {
  const ref = useRef<HTMLDivElement>(null);
  const chartRef = useRef<ECharts | null>(null);

  // Mount-only: create the instance once, wire resize, dispose on unmount.
  useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current, undefined, { renderer: 'canvas' });
    chartRef.current = chart;

    const onResize = () => chart.resize();
    window.addEventListener('resize', onResize);
    return () => {
      window.removeEventListener('resize', onResize);
      chart.dispose();
      chartRef.current = null;
    };
  }, []);

  // Data effect: reuse the retained instance via setOption (no re-init).
  useEffect(() => {
    const chart = chartRef.current;
    if (!chart) return;

    const values = data.map((d) => d[2]);
    const dataMin = values.length ? Math.min(...values) : 0;
    const dataMax = values.length ? Math.max(...values) : 1;

    chart.setOption(
      {
        animation: false,
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
          inRange: { color: ['#1e3a8a', '#3b82f6', '#fbbf24', '#ef4444'] },
        },
        series: [
          {
            name: 'value',
            type: 'heatmap',
            data,
            label: { show: false },
          },
        ],
      },
      { notMerge: true },
    );
  }, [xLabels, yLabels, data]);

  return <div ref={ref} style={{ width: '100%', height }} />;
}

interface BarChartProps {
  categories: string[];
  values: number[];
  rotateLabels?: number;
  height?: number;
}

export function BarChart({
  categories,
  values,
  rotateLabels = 0,
  height = DEFAULT_HEIGHT,
}: BarChartProps) {
  const ref = useRef<HTMLDivElement>(null);
  const chartRef = useRef<ECharts | null>(null);

  // Mount-only: create the instance once, wire resize, dispose on unmount.
  useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current, undefined, { renderer: 'canvas' });
    chartRef.current = chart;

    const onResize = () => chart.resize();
    window.addEventListener('resize', onResize);
    return () => {
      window.removeEventListener('resize', onResize);
      chart.dispose();
      chartRef.current = null;
    };
  }, []);

  // Data effect: reuse the retained instance via setOption (no re-init).
  useEffect(() => {
    const chart = chartRef.current;
    if (!chart) return;

    chart.setOption(
      {
        animation: false,
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
            itemStyle: { color: '#3b82f6' },
          },
        ],
      },
      { notMerge: true },
    );
  }, [categories, values, rotateLabels]);

  return <div ref={ref} style={{ width: '100%', height }} />;
}
