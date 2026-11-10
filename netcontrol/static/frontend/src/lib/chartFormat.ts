/** Value formatters shared by the ECharts wrappers (axis ticks and tooltips). */

const SI_STEPS: [number, string][] = [
  [1e12, 'T'],
  [1e9, 'G'],
  [1e6, 'M'],
  [1e3, 'k'],
];

/** Scale a value to one decimal with an SI prefix: 1234567 -> ["1.2", "M"]. */
function siScale(v: number): [string, string] {
  const abs = Math.abs(v);
  for (const [step, prefix] of SI_STEPS) {
    if (abs >= step) return [(v / step).toFixed(1), prefix];
  }
  return [formatChartNumber(v), ''];
}

/** A plain number rounded to at most two decimals. */
export function formatChartNumber(v: number): string {
  return String(Math.round(v * 100) / 100);
}

/** Compact y-axis tick for a bits-per-second axis: 1234567890 -> "1.2G". */
export function formatBpsTick(v: number): string {
  const [n, prefix] = siScale(v);
  return n + prefix;
}

/** A bits-per-second value with its unit, for tooltips: 1234567890 -> "1.2 Gbps". */
export function formatBpsValue(v: number): string {
  const [n, prefix] = siScale(v);
  return `${n} ${prefix}bps`;
}

/**
 * Tooltip valueFormatter for a line chart. ECharts passes the y value, an
 * array for multi-dimensional points, or nothing for a gap.
 */
export function chartTooltipFormatter(unit: 'bps' | 'number'): (value: unknown) => string {
  const fmt = unit === 'bps' ? formatBpsValue : formatChartNumber;
  return (value) => {
    const v = Array.isArray(value) ? value[value.length - 1] : value;
    const n = typeof v === 'number' ? v : Number(v);
    if (v == null || v === '' || !Number.isFinite(n)) return '-';
    return fmt(n);
  };
}
