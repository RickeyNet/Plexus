import { useMemo } from 'react';

import { Modal } from '@/components/Modal';
import { useBillingPeriodUsage } from '@/api/reports';
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
    <Modal isOpen={isOpen} onClose={onClose} title="Billing Period Detail" size="large">
      {query.isPending && <p className="text-muted">Loading…</p>}
      {query.error && <p style={{ color: 'var(--danger)' }}>Failed: {(query.error as Error).message}</p>}
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
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.5rem', marginBottom: '1rem' }}>
              <Stat label="P95 In" value={formatBps(p.p95_in_bps)} />
              <Stat label="P95 Out" value={formatBps(p.p95_out_bps)} />
              <Stat
                label="P95 Billing"
                value={formatBps(p.p95_billing_bps)}
                color={isOverage ? 'var(--danger)' : 'var(--success)'}
              />
              <Stat label="Commit Rate" value={formatBps(p.commit_rate_bps)} />
            </div>
            {isOverage && (
              <div className="card" style={{ padding: '0.75rem', background: 'rgba(220, 38, 38, 0.1)', marginBottom: '1rem' }}>
                <strong style={{ color: 'var(--danger)' }}>Overage Detected:</strong>{' '}
                {formatBps(p.overage_bps)} over commit - Cost: ${(p.overage_cost ?? 0).toLocaleString()}
              </div>
            )}
            {series.length ? (
              <TimeSeriesChart series={series} yAxisName="Mbps" height={300} />
            ) : (
              <p className="text-muted">No usage samples for this period.</p>
            )}
          </>
        );
      })()}
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
        <button className="btn btn-secondary" onClick={onClose}>Close</button>
      </div>
    </Modal>
  );
}

function Stat({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div className="card stat-card" style={{ padding: '0.75rem', textAlign: 'center' }}>
      <div className="stat-value" style={{ fontSize: '1.1rem', ...(color ? { color } : null) }}>{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}
