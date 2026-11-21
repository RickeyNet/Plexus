import { useMemo } from 'react';

import { type TopologyAvailabilityEntity, useTopologyEntityMetrics } from '@/api/monitoring';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import { StatGrid, StatTile } from '@/components/StatTile';
import { TimeSeriesChart } from '@/lib/echart';

import { entityMetricCharts, formatTraffic } from './topologyMetrics';

/**
 * What the vendor measures of one tracked entity over the period: the
 * window means and a chart per measurement it has samples of (an OPNsense
 * gateway's latency, jitter and loss; a tunnel's traffic in / out).
 */
export function TopologyEntityMetricsModal({
  entity,
  days,
  onClose,
}: {
  entity: TopologyAvailabilityEntity;
  days: number;
  onClose: () => void;
}) {
  const history = useTopologyEntityMetrics(entity, days);
  const charts = useMemo(() => entityMetricCharts(history.data?.samples ?? []), [history.data]);
  const summary = history.data?.summary;
  const tiles = [
    { label: 'Avg latency', value: summary?.avg_latency_ms, text: (v: number) => `${v.toFixed(1)} ms` },
    { label: 'Avg jitter', value: summary?.jitter_ms, text: (v: number) => `${v.toFixed(1)} ms` },
    { label: 'Avg loss', value: summary?.avg_packet_loss_pct, text: (v: number) => `${v.toFixed(2)}%` },
  ].filter((t) => typeof t.value === 'number');
  const traffic = formatTraffic(summary?.avg_in_bps, summary?.avg_out_bps);

  return (
    <Modal isOpen onClose={onClose} title={`Measurements: ${entity.name}`} size="large">
      {history.error && !history.data ? (
        <QueryError what="measurements" query={history} />
      ) : history.isPending ? (
        <LoadingState />
      ) : (
        <div className="stack">
          {(tiles.length > 0 || traffic !== '-') && (
            <StatGrid compact>
              {tiles.map((t) => (
                <StatTile key={t.label} center label={`${t.label} (${days}d)`} value={t.text(t.value as number)} />
              ))}
              {traffic !== '-' && <StatTile center label={`Avg traffic (${days}d)`} value={traffic} />}
            </StatGrid>
          )}
          {charts.length === 0 ? (
            <EmptyState compact message={`No measurements retained for the last ${days} days.`} />
          ) : (
            charts.map((c) => (
              <div className="card" key={c.key}>
                <div style={{ fontWeight: 600, marginBottom: '0.5rem' }}>{c.title}</div>
                <TimeSeriesChart series={c.series} unit={c.unit} valueFormatter={c.valueFormatter} yMin={0} height={200} />
              </div>
            ))
          )}
        </div>
      )}
    </Modal>
  );
}
