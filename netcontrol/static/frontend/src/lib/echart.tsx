import { useEffect, useRef } from 'react';
import * as echarts from 'echarts';

export interface TimeSeriesPoint {
  time: string;
  value: number;
}

export interface TimeSeries {
  name: string;
  data: TimeSeriesPoint[];
  color?: string;
}

interface TimeSeriesChartProps {
  series: TimeSeries[];
  area?: boolean;
  yAxisName?: string;
  yMin?: number;
  yMax?: number;
  height?: number;
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
}: TimeSeriesChartProps) {
  const ref = useRef<HTMLDivElement>(null);
  const chartRef = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current, undefined, { renderer: 'canvas' });
    chartRef.current = chart;

    const isBpsAxis = yAxisName === 'bps';

    chart.setOption({
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
      series: series.map((s) => ({
        name: s.name,
        type: 'line',
        showSymbol: false,
        smooth: false,
        sampling: 'lttb',
        itemStyle: s.color ? { color: s.color } : undefined,
        lineStyle: { width: 1.5 },
        areaStyle: area ? { opacity: 0.2 } : undefined,
        data: s.data.map((p) => [p.time, p.value]),
      })),
    });

    const onResize = () => chart.resize();
    window.addEventListener('resize', onResize);
    return () => {
      window.removeEventListener('resize', onResize);
      chart.dispose();
      chartRef.current = null;
    };
  }, [series, area, yAxisName, yMin, yMax]);

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

  useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current, undefined, { renderer: 'canvas' });

    chart.setOption({
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
    });

    const onResize = () => chart.resize();
    window.addEventListener('resize', onResize);
    return () => {
      window.removeEventListener('resize', onResize);
      chart.dispose();
    };
  }, [categories, values, rotateLabels]);

  return <div ref={ref} style={{ width: '100%', height }} />;
}
