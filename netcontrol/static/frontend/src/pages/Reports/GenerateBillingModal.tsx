import { useId, useState, type FormEvent } from 'react';

import { Callout } from '@/components/Callout';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import { useDialogs } from '@/components/DialogProvider-context';
import { useBillingCircuits, useGenerateBilling } from '@/api/reports';

interface Props {
  isOpen: boolean;
  onClose: () => void;
}

export function GenerateBillingModal({ isOpen, onClose }: Props) {
  const { alert } = useDialogs();
  const formId = useId();
  const [saveError, setSaveError] = useState('');
  const circuitsQuery = useBillingCircuits(undefined, true);
  const generateMut = useGenerateBilling();

  const [circuitId, setCircuitId] = useState('');
  const [start, setStart] = useState('');
  const [end, setEnd] = useState('');

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSaveError('');
    const payload: Parameters<typeof generateMut.mutate>[0] = {};
    if (circuitId) payload.circuit_id = parseInt(circuitId, 10);
    if (start) payload.period_start = `${start}T00:00:00Z`;
    if (end) payload.period_end = `${end}T00:00:00Z`;
    generateMut.mutate(payload, {
      onSuccess: (r) => {
        const count = r?.count ?? 0;
        const overages = (r?.periods ?? []).filter((p) => p.status === 'overage').length;
        void alert(`Generated ${count} billing period(s)${overages > 0 ? ` - ${overages} overage(s) detected` : ''}`);
        onClose();
      },
      onError: (err) => {
        setSaveError((err as Error).message);
      },
    });
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Generate 95th Percentile Billing"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={generateMut.isPending}>
            {generateMut.isPending ? 'Generating…' : 'Generate'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-circuit`}>Circuit (optional - leave blank for all)</label>
          <select id={`${formId}-circuit`} className="form-select" value={circuitId} onChange={(e) => setCircuitId(e.target.value)}>
            <option value="">All enabled circuits</option>
            {(circuitsQuery.data?.circuits ?? []).map((c) => (
              <option key={c.id} value={c.id}>{c.name} - {c.customer || 'No customer'}</option>
            ))}
          </select>
          {circuitsQuery.isError && !circuitsQuery.data && (
            <QueryError what="billing circuits" query={circuitsQuery} />
          )}
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-period-start`}>Period Start</label>
            <input id={`${formId}-period-start`} className="form-input" type="date" value={start} onChange={(e) => setStart(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-period-end`}>Period End</label>
            <input id={`${formId}-period-end`} className="form-input" type="date" value={end} onChange={(e) => setEnd(e.target.value)} />
          </div>
        </div>
        <p className="text-muted" style={{ fontSize: '0.85rem' }}>
          Leave dates blank to auto-calculate the most recent completed billing cycle.
        </p>
      </form>
    </Modal>
  );
}
