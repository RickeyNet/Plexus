import { useState } from 'react';

import {
  billingExportUrl,
  useBillingCircuits,
  useBillingCustomers,
  useBillingPeriods,
  useBillingSummary,
  useDeleteBillingCircuit,
  type BillingCircuit,
  type BillingPeriod,
} from '@/api/reports';

import { CircuitFormModal } from './CircuitFormModal';
import { GenerateBillingModal } from './GenerateBillingModal';
import { BillingPeriodModal } from './BillingPeriodModal';
import { formatBps } from './helpers';

export function BillingTab() {
  const [customer, setCustomer] = useState('');
  const [editingId, setEditingId] = useState<number | null | 'new'>(null);
  const [generating, setGenerating] = useState(false);
  const [periodId, setPeriodId] = useState<number | null>(null);

  const customersQuery = useBillingCustomers();
  const summaryQuery = useBillingSummary(customer || undefined);
  const circuitsQuery = useBillingCircuits(customer || undefined);
  const periodsQuery = useBillingPeriods(customer || undefined);
  const deleteMut = useDeleteBillingCircuit();

  const summary = summaryQuery.data;
  const circuits: BillingCircuit[] = circuitsQuery.data?.circuits ?? [];
  const periods: BillingPeriod[] = periodsQuery.data?.periods ?? [];

  function handleDelete(id: number) {
    if (!confirm('Delete this billing circuit and all its periods?')) return;
    deleteMut.mutate(id, {
      onError: (e) => alert((e as Error).message),
    });
  }

  return (
    <div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'flex-end', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
        <div className="form-group" style={{ marginBottom: 0 }}>
          <label className="form-label">Customer</label>
          <select className="form-select" value={customer} onChange={(e) => setCustomer(e.target.value)}>
            <option value="">All Customers</option>
            {(customersQuery.data?.customers ?? []).map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <a className="btn btn-secondary" href={billingExportUrl(customer || undefined)} download>
            Export CSV
          </a>
          <button className="btn btn-secondary" onClick={() => setGenerating(true)}>Generate Billing</button>
          <button className="btn btn-primary" onClick={() => setEditingId('new')}>+ New Circuit</button>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '0.75rem', marginBottom: '0.75rem' }}>
        <Card label="Total Circuits" value={String(summary?.total_circuits ?? 0)} />
        <Card label="Enabled" value={String(summary?.enabled_circuits ?? 0)} />
        <Card label="Billing Periods" value={String(summary?.total_periods ?? 0)} />
        <Card
          label="Overages"
          value={String(summary?.overage_periods ?? 0)}
          color={(summary?.overage_periods ?? 0) > 0 ? 'var(--danger)' : 'var(--success)'}
        />
        <Card
          label="Total Overage Cost"
          value={summary?.total_overage_cost ? `$${summary.total_overage_cost.toLocaleString()}` : '$0'}
        />
      </div>

      <h4>Circuits</h4>
      {circuitsQuery.isPending && <p className="text-muted">Loading…</p>}
      {circuitsQuery.error && <p style={{ color: 'var(--danger)' }}>Failed: {(circuitsQuery.error as Error).message}</p>}
      {circuitsQuery.data && (circuits.length === 0 ? (
        <div className="empty-state">
          <h4>No billing circuits defined</h4>
          <p className="text-muted">Create a billing circuit to start tracking 95th percentile bandwidth usage.</p>
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Name</th><th>Customer</th><th>Device</th><th>Interface</th>
                <th>Commit Rate</th><th>Cost/Mbps</th><th>Cycle</th><th>Status</th><th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {circuits.map((c) => (
                <tr key={c.id}>
                  <td>{c.name}</td>
                  <td>{c.customer || '—'}</td>
                  <td>{c.hostname || '—'}</td>
                  <td>{c.if_name || (c.if_index != null ? `idx:${c.if_index}` : '—')}</td>
                  <td>{formatBps(c.commit_rate_bps)}</td>
                  <td>{(c.cost_per_mbps ?? 0) > 0 ? `$${(c.cost_per_mbps ?? 0).toFixed(2)}` : '—'}</td>
                  <td>{c.billing_cycle}</td>
                  <td>{c.enabled
                    ? <span style={{ color: 'var(--success)' }}>Enabled</span>
                    : <span style={{ color: 'var(--text-muted)' }}>Disabled</span>}
                  </td>
                  <td style={{ display: 'flex', gap: '0.25rem' }}>
                    <button className="btn btn-sm btn-secondary" onClick={() => setEditingId(c.id)}>Edit</button>
                    <button className="btn btn-sm btn-danger" onClick={() => handleDelete(c.id)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}

      <h4 style={{ marginTop: '1rem' }}>Billing Periods</h4>
      {periodsQuery.isPending && <p className="text-muted">Loading…</p>}
      {periodsQuery.error && <p style={{ color: 'var(--danger)' }}>Failed: {(periodsQuery.error as Error).message}</p>}
      {periodsQuery.data && (periods.length === 0 ? (
        <div className="empty-state">
          <h4>No billing periods generated</h4>
          <p className="text-muted">Generate billing to calculate 95th percentile reports.</p>
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Period</th><th>Customer</th><th>Circuit</th><th>Device</th>
                <th>P95 In</th><th>P95 Out</th><th>P95 Billing</th>
                <th>Commit</th><th>Overage</th><th>Cost</th><th>Status</th><th></th>
              </tr>
            </thead>
            <tbody>
              {periods.map((p) => {
                const isOverage = p.status === 'overage';
                return (
                  <tr key={p.id}>
                    <td>{(p.period_start ?? '').slice(0, 10)} – {(p.period_end ?? '').slice(0, 10)}</td>
                    <td>{p.customer || '—'}</td>
                    <td>{p.circuit_name || '—'}</td>
                    <td>{p.hostname || '—'}</td>
                    <td>{formatBps(p.p95_in_bps)}</td>
                    <td>{formatBps(p.p95_out_bps)}</td>
                    <td><strong>{formatBps(p.p95_billing_bps)}</strong></td>
                    <td>{formatBps(p.commit_rate_bps)}</td>
                    <td>{isOverage ? <span style={{ color: 'var(--danger)' }}>{formatBps(p.overage_bps)}</span> : '—'}</td>
                    <td>{(p.overage_cost ?? 0) > 0 ? <span style={{ color: 'var(--danger)' }}>${p.overage_cost?.toLocaleString()}</span> : '—'}</td>
                    <td><span className={`badge ${isOverage ? 'badge-danger' : 'badge-success'}`}>{p.status}</span></td>
                    <td><button className="btn btn-sm btn-secondary" onClick={() => setPeriodId(p.id)}>View</button></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ))}

      <CircuitFormModal
        mode={editingId === 'new' ? 'create' : editingId != null ? 'edit' : null}
        circuitId={typeof editingId === 'number' ? editingId : null}
        onClose={() => setEditingId(null)}
      />
      <GenerateBillingModal isOpen={generating} onClose={() => setGenerating(false)} />
      <BillingPeriodModal periodId={periodId} onClose={() => setPeriodId(null)} />
    </div>
  );
}

function Card({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div className="card stat-card" style={{ padding: '0.85rem' }}>
      <div className="stat-value" style={color ? { color } : undefined}>{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}
