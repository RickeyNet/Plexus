import { useMemo, useState, type FormEvent } from 'react';

import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
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
  const { alert } = useDialogs();
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

  const hosts = useMemo(() => {
    const all = (groupsQuery.data ?? []).flatMap((g) => g.hosts ?? []);
    const seen = new Set<number>();
    return all.filter((h) => (seen.has(h.id) ? false : (seen.add(h.id), true)));
  }, [groupsQuery.data]);

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const hid = parseInt(hostId, 10);
    const idx = parseInt(ifIndex, 10);
    if (!hid || isNaN(idx)) {
      void alert('Device and interface index are required');
      return;
    }
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
        void alert({ message: (err as Error).message, variant: 'error' });
      },
    });
  }

  return (
    <Modal isOpen onClose={onClose} title="Create Billing Circuit" size="large">
      <form onSubmit={handleSubmit}>
        <div className="form-group"><label className="form-label">Circuit Name</label>
          <input className="form-input" value={name} onChange={(e) => setName(e.target.value)} required /></div>
        <div className="form-group"><label className="form-label">Customer</label>
          <input className="form-input" value={customer} onChange={(e) => setCustomer(e.target.value)} /></div>
        <div className="form-group"><label className="form-label">Device</label>
          <select className="form-select" value={hostId} onChange={(e) => setHostId(e.target.value)} required>
            <option value="">Select device…</option>
            {hosts.map((h) => <option key={h.id} value={h.id}>{h.hostname || h.ip_address}</option>)}
          </select></div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <div className="form-group"><label className="form-label">Interface Index</label>
            <input className="form-input" type="number" value={ifIndex} onChange={(e) => setIfIndex(e.target.value)} required /></div>
          <div className="form-group"><label className="form-label">Interface Name</label>
            <input className="form-input" value={ifName} onChange={(e) => setIfName(e.target.value)} placeholder="e.g. GigabitEthernet0/0/0" /></div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <div className="form-group"><label className="form-label">Commit Rate (bps)</label>
            <input className="form-input" type="number" value={commit} onChange={(e) => setCommit(e.target.value)} /></div>
          <div className="form-group"><label className="form-label">Burst Limit (bps)</label>
            <input className="form-input" type="number" value={burst} onChange={(e) => setBurst(e.target.value)} /></div>
          <div className="form-group"><label className="form-label">Cost per Mbps</label>
            <input className="form-input" type="number" step="0.01" value={cost} onChange={(e) => setCost(e.target.value)} /></div>
          <div className="form-group"><label className="form-label">Currency</label>
            <input className="form-input" value={currency} onChange={(e) => setCurrency(e.target.value)} /></div>
          <div className="form-group"><label className="form-label">Billing Day</label>
            <input className="form-input" type="number" min={1} max={28} value={billingDay} onChange={(e) => setBillingDay(e.target.value)} /></div>
          <div className="form-group"><label className="form-label">Billing Cycle</label>
            <select className="form-select" value={billingCycle} onChange={(e) => setBillingCycle(e.target.value)}>
              <option value="monthly">Monthly</option>
              <option value="weekly">Weekly</option>
            </select></div>
        </div>
        <div className="form-group"><label className="form-label">Description</label>
          <textarea className="form-textarea" rows={2} value={description} onChange={(e) => setDescription(e.target.value)} /></div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={createMut.isPending}>
            {createMut.isPending ? 'Creating…' : 'Create'}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function EditMode({ circuitId, onClose }: { circuitId: number; onClose: () => void }) {
  const { alert } = useDialogs();
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
        void alert({ message: (err as Error).message, variant: 'error' });
      },
    });
  }

  return (
    <Modal isOpen onClose={onClose} title="Edit Billing Circuit">
      {query.isPending ? (
        <p className="text-muted">Loading…</p>
      ) : (
        <form onSubmit={handleSubmit}>
          <div className="form-group"><label className="form-label">Circuit Name</label>
            <input className="form-input" value={name} onChange={(e) => setName(e.target.value)} /></div>
          <div className="form-group"><label className="form-label">Customer</label>
            <input className="form-input" value={customer} onChange={(e) => setCustomer(e.target.value)} /></div>
          <div className="form-group"><label className="form-label">Commit Rate (bps)</label>
            <input className="form-input" type="number" value={commit} onChange={(e) => setCommit(e.target.value)} /></div>
          <div className="form-group"><label className="form-label">Cost per Mbps</label>
            <input className="form-input" type="number" step="0.01" value={cost} onChange={(e) => setCost(e.target.value)} /></div>
          <div className="form-group"><label className="form-label">Billing Day</label>
            <input className="form-input" type="number" min={1} max={28} value={billingDay} onChange={(e) => setBillingDay(e.target.value)} /></div>
          <div className="form-group"><label className="form-label">Enabled</label>
            <select className="form-select" value={enabled} onChange={(e) => setEnabled(e.target.value)}>
              <option value="1">Yes</option>
              <option value="0">No</option>
            </select></div>
          <div className="form-group"><label className="form-label">Description</label>
            <textarea className="form-textarea" rows={2} value={description} onChange={(e) => setDescription(e.target.value)} /></div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
            <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={updateMut.isPending}>
              {updateMut.isPending ? 'Saving…' : 'Save'}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}
