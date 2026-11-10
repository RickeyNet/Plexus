import { useId, useMemo, useState, type FormEvent } from 'react';

import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import { useInventoryGroupsFull } from '@/api/inventory';
import {
  useBillingCircuit,
  useCreateBillingCircuit,
  useUpdateBillingCircuit,
  type BillingCircuitCreate,
  type BillingCircuitUpdate,
} from '@/api/reports';

interface Props {
  mode: 'create' | 'edit' | null;
  circuitId: number | null;
  onClose: () => void;
}

export function CircuitFormModal({ mode, circuitId, onClose }: Props) {
  const isOpen = mode != null;
  if (!isOpen) return null;
  return mode === 'edit' && circuitId != null
    ? <EditMode circuitId={circuitId} onClose={onClose} />
    : <CreateMode onClose={onClose} />;
}

function CreateMode({ onClose }: { onClose: () => void }) {
  const formId = useId();
  const groupsQuery = useInventoryGroupsFull(true);
  const createMut = useCreateBillingCircuit();

  const [name, setName] = useState('');
  const [customer, setCustomer] = useState('');
  const [hostId, setHostId] = useState('');
  const [ifIndex, setIfIndex] = useState('');
  const [ifName, setIfName] = useState('');
  const [commit, setCommit] = useState('0');
  const [burst, setBurst] = useState('0');
  const [cost, setCost] = useState('0');
  const [currency, setCurrency] = useState('USD');
  const [billingDay, setBillingDay] = useState('1');
  const [billingCycle, setBillingCycle] = useState('monthly');
  const [description, setDescription] = useState('');
  const [hostError, setHostError] = useState('');
  const [ifIndexError, setIfIndexError] = useState('');
  const [saveError, setSaveError] = useState('');

  const hosts = useMemo(() => {
    const all = (groupsQuery.data ?? []).flatMap((g) => g.hosts ?? []);
    const seen = new Set<number>();
    return all.filter((h) => (seen.has(h.id) ? false : (seen.add(h.id), true)));
  }, [groupsQuery.data]);

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const hid = parseInt(hostId, 10);
    const idx = parseInt(ifIndex, 10);
    setSaveError('');
    const hostErr = hid ? '' : 'Device is required';
    const ifIndexErr = isNaN(idx) ? 'Interface index is required' : '';
    setHostError(hostErr);
    setIfIndexError(ifIndexErr);
    if (hostErr || ifIndexErr) return;
    const payload: BillingCircuitCreate = {
      name,
      customer,
      host_id: hid,
      if_index: idx,
      if_name: ifName,
      commit_rate_bps: parseFloat(commit) || 0,
      burst_limit_bps: parseFloat(burst) || 0,
      cost_per_mbps: parseFloat(cost) || 0,
      currency,
      billing_day: parseInt(billingDay, 10) || 1,
      billing_cycle: billingCycle,
      description,
    };
    createMut.mutate(payload, {
      onSuccess: onClose,
      onError: (err) => {
        setSaveError((err as Error).message);
      },
    });
  }

  return (
    <Modal
      isOpen
      onClose={onClose}
      title="Create Billing Circuit"
      size="medium"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={createMut.isPending}>
            {createMut.isPending ? 'Creating…' : 'Create'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        <div className="form-group"><label className="form-label" htmlFor={`${formId}-circuit-name`}>Circuit Name</label>
          <input id={`${formId}-circuit-name`} className="form-input" value={name} onChange={(e) => setName(e.target.value)} required /></div>
        <div className="form-group"><label className="form-label" htmlFor={`${formId}-customer`}>Customer</label>
          <input id={`${formId}-customer`} className="form-input" value={customer} onChange={(e) => setCustomer(e.target.value)} /></div>
        <div className="form-group"><label className="form-label" htmlFor={`${formId}-device`}>Device</label>
          <select
            id={`${formId}-device`}
            className="form-select"
            value={hostId}
            onChange={(e) => { setHostId(e.target.value); setHostError(''); }}
            aria-invalid={!!hostError}
            required
          >
            <option value="">Select device…</option>
            {hosts.map((h) => <option key={h.id} value={h.id}>{h.hostname || h.ip_address}</option>)}
          </select>
          <FieldError>{hostError}</FieldError>
          {groupsQuery.isError && !groupsQuery.data && (
            <QueryError what="inventory devices" query={groupsQuery} />
          )}</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <div className="form-group"><label className="form-label" htmlFor={`${formId}-interface-index`}>Interface Index</label>
            <input
              id={`${formId}-interface-index`}
              className="form-input"
              type="number"
              value={ifIndex}
              onChange={(e) => { setIfIndex(e.target.value); setIfIndexError(''); }}
              aria-invalid={!!ifIndexError}
              required
            />
            <FieldError>{ifIndexError}</FieldError></div>
          <div className="form-group"><label className="form-label" htmlFor={`${formId}-interface-name`}>Interface Name</label>
            <input id={`${formId}-interface-name`} className="form-input" value={ifName} onChange={(e) => setIfName(e.target.value)} placeholder="e.g. GigabitEthernet0/0/0" /></div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <div className="form-group"><label className="form-label" htmlFor={`${formId}-commit-rate`}>Commit Rate (bps)</label>
            <input id={`${formId}-commit-rate`} className="form-input" type="number" value={commit} onChange={(e) => setCommit(e.target.value)} /></div>
          <div className="form-group"><label className="form-label" htmlFor={`${formId}-burst-limit`}>Burst Limit (bps)</label>
            <input id={`${formId}-burst-limit`} className="form-input" type="number" value={burst} onChange={(e) => setBurst(e.target.value)} /></div>
          <div className="form-group"><label className="form-label" htmlFor={`${formId}-cost-mbps`}>Cost per Mbps</label>
            <input id={`${formId}-cost-mbps`} className="form-input" type="number" step="0.01" value={cost} onChange={(e) => setCost(e.target.value)} /></div>
          <div className="form-group"><label className="form-label" htmlFor={`${formId}-currency`}>Currency</label>
            <input id={`${formId}-currency`} className="form-input" value={currency} onChange={(e) => setCurrency(e.target.value)} /></div>
          <div className="form-group"><label className="form-label" htmlFor={`${formId}-billing-day`}>Billing Day</label>
            <input id={`${formId}-billing-day`} className="form-input" type="number" min={1} max={28} value={billingDay} onChange={(e) => setBillingDay(e.target.value)} /></div>
          <div className="form-group"><label className="form-label" htmlFor={`${formId}-billing-cycle`}>Billing Cycle</label>
            <select id={`${formId}-billing-cycle`} className="form-select" value={billingCycle} onChange={(e) => setBillingCycle(e.target.value)}>
              <option value="monthly">Monthly</option>
              <option value="weekly">Weekly</option>
            </select></div>
        </div>
        <div className="form-group"><label className="form-label" htmlFor={`${formId}-description`}>Description</label>
          <textarea id={`${formId}-description`} className="form-textarea" rows={2} value={description} onChange={(e) => setDescription(e.target.value)} /></div>
      </form>
    </Modal>
  );
}

function EditMode({ circuitId, onClose }: { circuitId: number; onClose: () => void }) {
  const formId = useId();
  const [saveError, setSaveError] = useState('');
  const query = useBillingCircuit(circuitId);
  const updateMut = useUpdateBillingCircuit();

  const [name, setName] = useState('');
  const [customer, setCustomer] = useState('');
  const [commit, setCommit] = useState('0');
  const [cost, setCost] = useState('0');
  const [billingDay, setBillingDay] = useState('1');
  const [enabled, setEnabled] = useState('1');
  const [description, setDescription] = useState('');

  const [prevData, setPrevData] = useState(query.data);
  if (query.data !== prevData) {
    setPrevData(query.data);
    const c = query.data;
    if (c) {
      setName(c.name ?? '');
      setCustomer(c.customer ?? '');
      setCommit(String(c.commit_rate_bps ?? 0));
      setCost(String(c.cost_per_mbps ?? 0));
      setBillingDay(String(c.billing_day ?? 1));
      setEnabled(c.enabled ? '1' : '0');
      setDescription(c.description ?? '');
    }
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSaveError('');
    const data: BillingCircuitUpdate = {
      name,
      customer,
      commit_rate_bps: parseFloat(commit) || 0,
      cost_per_mbps: parseFloat(cost) || 0,
      billing_day: parseInt(billingDay, 10) || 1,
      enabled: parseInt(enabled, 10),
      description,
    };
    updateMut.mutate({ id: circuitId, data }, {
      onSuccess: onClose,
      onError: (err) => {
        setSaveError((err as Error).message);
      },
    });
  }

  return (
    <Modal
      isOpen
      onClose={onClose}
      title="Edit Billing Circuit"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button
            type="submit"
            form={formId}
            className="btn btn-primary"
            disabled={updateMut.isPending || !query.data}
          >
            {updateMut.isPending ? 'Saving…' : 'Save'}
          </button>
        </>
      }
    >
      {query.isError && !query.data ? (
        <QueryError what="billing circuit" query={query} />
      ) : query.isPending ? (
        <LoadingState />
      ) : (
        <form id={formId} onSubmit={handleSubmit}>
          {saveError && <Callout tone="danger">{saveError}</Callout>}
          <div className="form-group"><label className="form-label" htmlFor={`${formId}-circuit-name-2`}>Circuit Name</label>
            <input id={`${formId}-circuit-name-2`} className="form-input" value={name} onChange={(e) => setName(e.target.value)} /></div>
          <div className="form-group"><label className="form-label" htmlFor={`${formId}-customer-2`}>Customer</label>
            <input id={`${formId}-customer-2`} className="form-input" value={customer} onChange={(e) => setCustomer(e.target.value)} /></div>
          <div className="form-group"><label className="form-label" htmlFor={`${formId}-commit-rate-2`}>Commit Rate (bps)</label>
            <input id={`${formId}-commit-rate-2`} className="form-input" type="number" value={commit} onChange={(e) => setCommit(e.target.value)} /></div>
          <div className="form-group"><label className="form-label" htmlFor={`${formId}-cost-mbps-2`}>Cost per Mbps</label>
            <input id={`${formId}-cost-mbps-2`} className="form-input" type="number" step="0.01" value={cost} onChange={(e) => setCost(e.target.value)} /></div>
          <div className="form-group"><label className="form-label" htmlFor={`${formId}-billing-day-2`}>Billing Day</label>
            <input id={`${formId}-billing-day-2`} className="form-input" type="number" min={1} max={28} value={billingDay} onChange={(e) => setBillingDay(e.target.value)} /></div>
          <div className="form-group"><label className="form-label" htmlFor={`${formId}-enabled`}>Enabled</label>
            <select id={`${formId}-enabled`} className="form-select" value={enabled} onChange={(e) => setEnabled(e.target.value)}>
              <option value="1">Yes</option>
              <option value="0">No</option>
            </select></div>
          <div className="form-group"><label className="form-label" htmlFor={`${formId}-description-2`}>Description</label>
            <textarea id={`${formId}-description-2`} className="form-textarea" rows={2} value={description} onChange={(e) => setDescription(e.target.value)} /></div>
        </form>
      )}
    </Modal>
  );
}
