import { useId, useMemo, useState, type FormEvent, type ReactNode } from 'react';

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
  type BillingCircuit,
  type BillingCircuitCreate,
  type BillingCircuitUpdate,
} from '@/api/reports';

interface Props {
  mode: 'create' | 'edit' | null;
  circuitId: number | null;
  onClose: () => void;
}

/** The fields create and edit share, held as the strings the inputs show. */
interface CircuitFields {
  name: string;
  customer: string;
  ifName: string;
  commit: string;
  burst: string;
  cost: string;
  currency: string;
  billingDay: string;
  billingCycle: string;
  description: string;
}

const EMPTY_FIELDS: CircuitFields = {
  name: '',
  customer: '',
  ifName: '',
  commit: '0',
  burst: '0',
  cost: '0',
  currency: 'USD',
  billingDay: '1',
  billingCycle: 'monthly',
  description: '',
};

function fieldsFromCircuit(c: BillingCircuit): CircuitFields {
  return {
    name: c.name ?? '',
    customer: c.customer ?? '',
    ifName: c.if_name ?? '',
    commit: String(c.commit_rate_bps ?? 0),
    burst: String(c.burst_limit_bps ?? 0),
    cost: String(c.cost_per_mbps ?? 0),
    currency: c.currency ?? 'USD',
    billingDay: String(c.billing_day ?? 1),
    billingCycle: c.billing_cycle ?? 'monthly',
    description: c.description ?? '',
  };
}

/** The part of the API payload create and edit have in common. */
function fieldsPayload(f: CircuitFields) {
  return {
    name: f.name,
    customer: f.customer,
    if_name: f.ifName,
    commit_rate_bps: parseFloat(f.commit) || 0,
    burst_limit_bps: parseFloat(f.burst) || 0,
    cost_per_mbps: parseFloat(f.cost) || 0,
    currency: f.currency,
    billing_day: parseInt(f.billingDay, 10) || 1,
    billing_cycle: f.billingCycle,
    description: f.description,
  };
}

const GRID = { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' } as const;

export function CircuitFormModal({ mode, circuitId, onClose }: Props) {
  const isOpen = mode != null;
  if (!isOpen) return null;
  return mode === 'edit' && circuitId != null
    ? <EditMode circuitId={circuitId} onClose={onClose} />
    : <CreateMode onClose={onClose} />;
}

/**
 * The one circuit form. Create and edit differ only in the device and
 * interface-index controls (fixed once a circuit exists) and in the extra
 * Enabled control, which the callers pass in.
 */
function CircuitFormBody({
  formId,
  fields,
  onChange,
  onSubmit,
  saveError,
  device,
  interfaceIndex,
  extra,
}: {
  formId: string;
  fields: CircuitFields;
  onChange: (patch: Partial<CircuitFields>) => void;
  onSubmit: (e: FormEvent) => void;
  saveError: string;
  device: ReactNode;
  interfaceIndex: ReactNode;
  extra?: ReactNode;
}) {
  return (
    <form id={formId} onSubmit={onSubmit}>
      {saveError && <Callout tone="danger">{saveError}</Callout>}
      <div className="form-group"><label className="form-label" htmlFor={`${formId}-circuit-name`}>Circuit Name</label>
        <input id={`${formId}-circuit-name`} className="form-input" value={fields.name} onChange={(e) => onChange({ name: e.target.value })} required /></div>
      <div className="form-group"><label className="form-label" htmlFor={`${formId}-customer`}>Customer</label>
        <input id={`${formId}-customer`} className="form-input" value={fields.customer} onChange={(e) => onChange({ customer: e.target.value })} /></div>
      <div className="form-group"><label className="form-label" htmlFor={`${formId}-device`}>Device</label>
        {device}</div>
      <div style={GRID}>
        <div className="form-group"><label className="form-label" htmlFor={`${formId}-interface-index`}>Interface Index</label>
          {interfaceIndex}</div>
        <div className="form-group"><label className="form-label" htmlFor={`${formId}-interface-name`}>Interface Name</label>
          <input id={`${formId}-interface-name`} className="form-input" value={fields.ifName} onChange={(e) => onChange({ ifName: e.target.value })} placeholder="e.g. GigabitEthernet0/0/0" /></div>
      </div>
      <div style={GRID}>
        <div className="form-group"><label className="form-label" htmlFor={`${formId}-commit-rate`}>Commit Rate (bps)</label>
          <input id={`${formId}-commit-rate`} className="form-input" type="number" value={fields.commit} onChange={(e) => onChange({ commit: e.target.value })} /></div>
        <div className="form-group"><label className="form-label" htmlFor={`${formId}-burst-limit`}>Burst Limit (bps)</label>
          <input id={`${formId}-burst-limit`} className="form-input" type="number" value={fields.burst} onChange={(e) => onChange({ burst: e.target.value })} /></div>
        <div className="form-group"><label className="form-label" htmlFor={`${formId}-cost-mbps`}>Cost per Mbps</label>
          <input id={`${formId}-cost-mbps`} className="form-input" type="number" step="0.01" value={fields.cost} onChange={(e) => onChange({ cost: e.target.value })} /></div>
        <div className="form-group"><label className="form-label" htmlFor={`${formId}-currency`}>Currency</label>
          <input id={`${formId}-currency`} className="form-input" value={fields.currency} onChange={(e) => onChange({ currency: e.target.value })} /></div>
        <div className="form-group"><label className="form-label" htmlFor={`${formId}-billing-day`}>Billing Day</label>
          <input id={`${formId}-billing-day`} className="form-input" type="number" min={1} max={28} value={fields.billingDay} onChange={(e) => onChange({ billingDay: e.target.value })} /></div>
        <div className="form-group"><label className="form-label" htmlFor={`${formId}-billing-cycle`}>Billing Cycle</label>
          <select id={`${formId}-billing-cycle`} className="form-select" value={fields.billingCycle} onChange={(e) => onChange({ billingCycle: e.target.value })}>
            <option value="monthly">Monthly</option>
            <option value="weekly">Weekly</option>
          </select></div>
        {extra}
      </div>
      <div className="form-group"><label className="form-label" htmlFor={`${formId}-description`}>Description</label>
        <textarea id={`${formId}-description`} className="form-input" rows={2} value={fields.description} onChange={(e) => onChange({ description: e.target.value })} /></div>
    </form>
  );
}

function CreateMode({ onClose }: { onClose: () => void }) {
  const formId = useId();
  const groupsQuery = useInventoryGroupsFull(true);
  const createMut = useCreateBillingCircuit();

  const [fields, setFields] = useState<CircuitFields>(EMPTY_FIELDS);
  const [hostId, setHostId] = useState('');
  const [ifIndex, setIfIndex] = useState('');
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
    const payload: BillingCircuitCreate = { ...fieldsPayload(fields), host_id: hid, if_index: idx };
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
      <CircuitFormBody
        formId={formId}
        fields={fields}
        onChange={(patch) => setFields((f) => ({ ...f, ...patch }))}
        onSubmit={handleSubmit}
        saveError={saveError}
        device={
          <>
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
            )}
          </>
        }
        interfaceIndex={
          <>
            <input
              id={`${formId}-interface-index`}
              className="form-input"
              type="number"
              value={ifIndex}
              onChange={(e) => { setIfIndex(e.target.value); setIfIndexError(''); }}
              aria-invalid={!!ifIndexError}
              required
            />
            <FieldError>{ifIndexError}</FieldError>
          </>
        }
      />
    </Modal>
  );
}

function EditMode({ circuitId, onClose }: { circuitId: number; onClose: () => void }) {
  const formId = useId();
  const [saveError, setSaveError] = useState('');
  const query = useBillingCircuit(circuitId);
  const updateMut = useUpdateBillingCircuit();

  const [fields, setFields] = useState<CircuitFields>(EMPTY_FIELDS);
  const [enabled, setEnabled] = useState('1');

  const [prevData, setPrevData] = useState(query.data);
  if (query.data !== prevData) {
    setPrevData(query.data);
    const c = query.data;
    if (c) {
      setFields(fieldsFromCircuit(c));
      setEnabled(c.enabled ? '1' : '0');
    }
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSaveError('');
    const data: BillingCircuitUpdate = { ...fieldsPayload(fields), enabled: parseInt(enabled, 10) };
    updateMut.mutate({ id: circuitId, data }, {
      onSuccess: onClose,
      onError: (err) => {
        setSaveError((err as Error).message);
      },
    });
  }

  const circuit = query.data;

  return (
    <Modal
      isOpen
      onClose={onClose}
      title="Edit Billing Circuit"
      size="medium"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button
            type="submit"
            form={formId}
            className="btn btn-primary"
            disabled={updateMut.isPending || !circuit}
          >
            {updateMut.isPending ? 'Saving…' : 'Save'}
          </button>
        </>
      }
    >
      {query.isError && !circuit ? (
        <QueryError what="billing circuit" query={query} />
      ) : query.isPending ? (
        <LoadingState />
      ) : (
        <CircuitFormBody
          formId={formId}
          fields={fields}
          onChange={(patch) => setFields((f) => ({ ...f, ...patch }))}
          onSubmit={handleSubmit}
          saveError={saveError}
          device={
            <>
              <input
                id={`${formId}-device`}
                className="form-input"
                value={circuit?.hostname || (circuit?.host_id != null ? `Device #${circuit.host_id}` : '-')}
                disabled
              />
              <div className="form-help">The device and interface index are fixed once a circuit is created.</div>
            </>
          }
          interfaceIndex={
            <input
              id={`${formId}-interface-index`}
              className="form-input"
              value={circuit?.if_index ?? ''}
              disabled
            />
          }
          extra={
            <div className="form-group"><label className="form-label" htmlFor={`${formId}-enabled`}>Enabled</label>
              <select id={`${formId}-enabled`} className="form-select" value={enabled} onChange={(e) => setEnabled(e.target.value)}>
                <option value="1">Yes</option>
                <option value="0">No</option>
              </select></div>
          }
        />
      )}
    </Modal>
  );
}
