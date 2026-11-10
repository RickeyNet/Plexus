import { useEffect, useRef, type RefObject } from 'react';

import { echarts, type ECharts } from './echart-core';

/** The part of an ECharts instance the resize observer needs. */
export interface ResizableChart {
  resize: () => void;
  isDisposed?: () => boolean;
}

/**
 * Resize `chart` whenever `element` changes size (sidebar collapse, grid
 * reflow, edit mode), not only on window resize. Falls back to the window
 * resize event where ResizeObserver is missing (old browsers, the test
 * environment). Returns the cleanup function.
 */
export function observeChartResize(chart: ResizableChart, element: Element): () => void {
  const resize = () => {
    if (!chart.isDisposed?.()) chart.resize();
  };
  if (typeof ResizeObserver !== 'undefined') {
    const observer = new ResizeObserver(resize);
    observer.observe(element);
    return () => observer.disconnect();
  }
  if (typeof window !== 'undefined') {
    window.addEventListener('resize', resize);
    return () => window.removeEventListener('resize', resize);
  }
  return () => {};
}

/**
 * Create one ECharts instance on the element in `ref` when the component
 * mounts, keep it sized to that element, and dispose it on unmount. Declare
 * it before the effect that calls setOption so the instance exists when that
 * effect first runs.
 */
export function useEChart(ref: RefObject<HTMLElement | null>): RefObject<ECharts | null> {
  const chartRef = useRef<ECharts | null>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const chart = echarts.init(el, undefined, { renderer: 'canvas' });
    chartRef.current = chart;
    const stopObserving = observeChartResize(chart, el);
    return () => {
      stopObserving();
      chart.dispose();
      chartRef.current = null;
    };
  }, [ref]);

  return chartRef;
}
