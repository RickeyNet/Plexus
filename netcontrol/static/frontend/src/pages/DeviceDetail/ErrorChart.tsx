import { TimeSeriesChart, TimeSeries } from '@/lib/echart';
import { useInterfaceErrorDetail } from '@/api/deviceDetail';

const METRIC_LABELS: Record<string, string> = {
  if_in_errors_rate: 'In Errors/s',
  if_out_errors_rate: 'Out Errors/s',
  if_in_discards_rate: 'In Discards/s',
  if_out_discards_rate: 'Out Discards/s',
};

const METRIC_COLORS: Record<string, string> = {
  if_in_errors_rate: '#EF4444',
  if_out_errors_rate: '#F97316',
  if_in_discards_rate: '#A855F7',
  if_out_discards_rate: '#EC4899',
};

export function ErrorChart({ hostId, ifIndex }: { hostId: number; ifIndex: number }) {
  const { data, isLoading, isError } = useInterfaceErrorDetail(hostId, ifIndex, true);

  if (isLoading) {
    return <div style={{ height: 180 }} className="text-muted" />;
  }
  if (isError || !data) {
    return (
      <p className="text-muted" style={{ padding: '0.5rem' }}>
        Could not load
      </p>
    );
  }

  const series: TimeSeries[] = [];
  const seriesMap = data.series || {};
  for (const [key, label] of Object.entries(METRIC_LABELS)) {
    const points = (seriesMap[key] || []).map((d) => ({
      time: d.sampled_at,
      value: d.value || 0,
    }));
    if (points.length) {
      series.push({ name: label, data: points, color: METRIC_COLORS[key] });
    }
  }

  if (!series.length) {
    return (
      <p className="text-muted" style={{ padding: '0.5rem' }}>
        No error data
      </p>
    );
  }

  return <TimeSeriesChart height={180} yAxisName="errors/s" yMin={0} series={series} />;
}
