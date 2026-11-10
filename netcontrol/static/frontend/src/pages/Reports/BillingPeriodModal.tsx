import { useMemo } from 'react';

import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import { useBillingPeriodUsage } from '@/api/reports';
import { StatGrid, StatTile } from '@/components/StatTile';
import { TimeSeriesChart, type TimeSeries } from '@/lib/echart';

import { formatBps } from './helpers';

interface Props {
  periodId: number | null;
  onClose: () => void;
}

export function BillingPeriodModal({ periodId, onClose }: Props) {
  const isOpen = periodId != null;
  const query = useBillingPeriodUsage(periodId);

  const series: TimeSeries[] = useMemo(() => {
    const samples = query.data?.samples ?? [];
    if (!samples.length) return [];
    return [
      {
        name: 'Inbound (Mbps)',
        data: samples.map((s) => ({ time: s.sampled_at, value: (s.in_rate_bps ?? 0) / 1e6 })),
      },
      {
        name: 'Outbound (Mbps)',
        data: samples.map((s) => ({ time: s.sampled_at, value: (s.out_rate_bps ?? 0) / 1e6 })),
      },
    ];
  }, [query.data]);

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Billing Period Detail"
      size="medium"
      footer={<button type="button" className="btn btn-secondary" onClick={onClose}>Close</button>}
    >
      {query.isPending && <LoadingState />}
      {query.isError && !query.data && (
        <QueryError what="billing period usage" query={query} />
      )}
      {query.data && (() => {
        const p = query.data.period ?? {};
        const isOverage = p.status === 'overage';
        return (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginBottom: '1rem' }}>
              <div><strong>Circuit:</strong> {p.circuit_name || ''}</div>
              <div><strong>Customer:</strong> {p.customer || '-'}</div>
              <div><strong>Device:</strong> {p.hostname || '-'}</div>
              <div><strong>Interface:</strong> {p.if_name || ''}</div>
              <div><strong>Period:</strong> {(p.period_start ?? '').slice(0, 10)} – {(p.period_end ?? '').slice(0, 10)}</div>
              <div><strong>Samples:</strong> {p.total_samples ?? 0}</div>
            </div>
            <StatGrid compact>
              <StatTile center label="P95 In" value={formatBps(p.p95_in_bps)} />
              <StatTile center label="P95 Out" value={formatBps(p.p95_out_bps)} />
              <StatTile center
                label="P95 Billing"
                value={formatBps(p.p95_billing_bps)}
                tone={isOverage ? 'danger' : 'success'}
              />
              <StatTile center label="Commit Rate" value={formatBps(p.commit_rate_bps)} />
            </StatGrid>
            {isOverage && (
              <div className="card card-sm" style={{ background: 'rgba(from var(--danger) r g b / 0.1)', marginBottom: 'var(--space-4)' }}>
                <strong style={{ color: 'var(--danger)' }}>Overage Detected:</strong>{' '}
                {formatBps(p.overage_bps)} over commit - Cost: ${(p.overage_cost ?? 0).toLocaleString()}
              </div>
            )}
            {series.length ? (
              <TimeSeriesChart series={series} yAxisName="Mbps" height={300} />
            ) : (
              <EmptyState compact message="No usage samples for this period." />
            )}
          </>
        );
      })()}
    </Modal>
  );
}

