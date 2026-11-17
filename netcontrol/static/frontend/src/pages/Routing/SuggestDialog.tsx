import { useId, useState } from 'react';

import { type Suggestions, useAcceptSuggestions, useRoutingSuggestions } from '@/api/routing';
import { Callout } from '@/components/Callout';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { formatAsn, parseAsn } from '@/lib/routing';
import { serverFieldErrors } from '@/lib/serverFieldErrors';

import { Field } from './RoutingParts';

/**
 * Proposes peerings (and the AS numbers and instance they need) from the BGP
 * neighbors observed on one device. Nothing is created until the user picks
 * the rows and confirms; each row keeps the status the user chose.
 */
export function SuggestDialog({ hostId, onClose }: { hostId: number; onClose: () => void }) {
  const q = useRoutingSuggestions(hostId);
  return (
    <Modal isOpen onClose={onClose} size="large" title={q.data ? `Suggest from observed neighbors: ${q.data.hostname}` : 'Suggest from observed neighbors'}>
      {q.isError && !q.data ? (
        <QueryError what="suggestions" query={q} />
      ) : q.isPending ? (
        <LoadingState text="Reading observed neighbors…" />
      ) : (
        <SuggestForm data={q.data} onClose={onClose} />
      )}
    </Modal>
  );
}

function SuggestForm({ data, onClose }: { data: Suggestions; onClose: () => void }) {
  const id = useId();
  const accept = useAcceptSuggestions();
  const [instanceId, setInstanceId] = useState<number | null>(data.routing_instances[0]?.id ?? null);
  const [name, setName] = useState(data.proposed_instance?.name ?? 'default');
  const [localAsn, setLocalAsn] = useState('');
  const [picked, setPicked] = useState<Record<string, 'active' | 'planned' | null>>(() =>
    Object.fromEntries(data.peerings.map((p) => [p.remote_address, p.status])),
  );
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [failure, setFailure] = useState<string | null>(null);
  const newInstance = instanceId === null;
  const chosen = data.peerings.filter((p) => picked[p.remote_address]);

  if (!data.has_data) {
    return (
      <>
        <EmptyState compact message="No data for this device." description="Neighbor discovery has not run for it yet, so there is nothing to suggest." />
        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </>
    );
  }
  if (data.peerings.length === 0) {
    return (
      <>
        <EmptyState compact message="Nothing to suggest." description="Every observed BGP neighbor of this device already has a peering." />
        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </>
    );
  }

  const submit = async () => {
    const local: Record<string, string> = {};
    if (newInstance && parseAsn(localAsn) === null) local['new_instance.asn'] = 'Enter the local AS number of the new instance.';
    if (newInstance && !name.trim()) local['new_instance.name'] = 'Name is required.';
    if (!newInstance && chosen.length === 0) local.peerings = 'Select at least one neighbor.';
    setErrors(local);
    if (Object.keys(local).length) return;
    setFailure(null);
    try {
      await accept.mutateAsync({
        host_id: data.host_id,
        routing_instance_id: instanceId,
        new_instance: newInstance ? { name: name.trim(), asn: parseAsn(localAsn) as number, status: 'active' } : null,
        peerings: chosen.map((p) => ({
          remote_address: p.remote_address,
          remote_asn: p.remote_asn,
          status: picked[p.remote_address] as 'active' | 'planned',
          remote_host_id: p.remote_host_id,
        })),
      });
      onClose();
    } catch (err) {
      const fields = serverFieldErrors(err);
      if (Object.keys(fields).length) setErrors(fields);
      else setFailure((err as Error).message);
    }
  };

  const newAses = data.autonomous_systems.filter((a) => a.autonomous_system_id === null);
  return (
    <>
      {failure && (
        <Callout tone="danger" title="The suggestions were not recorded">
          {failure} Try again.
        </Callout>
      )}
      <p className="text-muted" style={{ marginTop: 0 }}>
        These BGP neighbors were observed on the device but have no intended peering. Pick the ones to record; established sessions are proposed as
        active, the rest as planned.
        {newAses.length > 0 && ` New AS records will be added for ${newAses.map((a) => formatAsn(a.asn)).join(', ')}.`}
      </p>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0 var(--space-3)' }}>
        <Field id={`${id}-instance`} label="Into routing instance" error={errors.routing_instance_id}>
          <select id={`${id}-instance`} className="form-select" value={instanceId ?? ''} onChange={(e) => setInstanceId(e.target.value ? Number(e.target.value) : null)}>
            {data.routing_instances.map((i) => (
              <option key={i.id} value={i.id}>
                {i.name} ({formatAsn(i.asn)})
              </option>
            ))}
            <option value="">New instance…</option>
          </select>
        </Field>
        {newInstance && (
          <>
            <Field id={`${id}-name`} label="New instance name" error={errors['new_instance.name']}>
              <input id={`${id}-name`} className="form-input" value={name} onChange={(e) => setName(e.target.value)} aria-invalid={!!errors['new_instance.name']} aria-describedby={`${id}-name-error`} />
            </Field>
            <Field id={`${id}-asn`} label="Local ASN" error={errors['new_instance.asn']} help="The device's own AS; discovery does not read it.">
              <input
                id={`${id}-asn`}
                className="form-input"
                value={localAsn}
                placeholder="65001"
                inputMode="numeric"
                onChange={(e) => setLocalAsn(e.target.value)}
                aria-invalid={!!errors['new_instance.asn']}
                aria-describedby={`${id}-asn-error`}
              />
            </Field>
          </>
        )}
      </div>
      <DataTable compact aria-label="Observed neighbors without a peering">
        <thead>
          <tr>
            <th>Record</th>
            <th>Remote</th>
            <th>Remote AS</th>
            <th>Observed state</th>
            <th>Status to record</th>
          </tr>
        </thead>
        <tbody>
          {data.peerings.map((p, index) => {
            const on = !!picked[p.remote_address];
            const rowError = errors[`peerings.${index}.remote_address`] || errors[`peerings.${index}.remote_asn`];
            return (
              <tr key={p.remote_address}>
                <td>
                  <input
                    type="checkbox"
                    aria-label={`Record a peering with ${p.remote_address}`}
                    checked={on}
                    onChange={() => setPicked((prev) => ({ ...prev, [p.remote_address]: on ? null : p.status }))}
                  />
                </td>
                <td>
                  {p.remote_address}
                  {p.remote_hostname && <div className="text-muted" style={{ fontSize: '0.85em' }}>{p.remote_hostname}</div>}
                  {rowError && <div className="form-error">{rowError}</div>}
                </td>
                <td>{formatAsn(p.remote_asn)}</td>
                <td>{p.observed_state || 'unknown'}</td>
                <td>
                  <select
                    className="form-select form-select-sm"
                    aria-label={`Status of the peering with ${p.remote_address}`}
                    disabled={!on}
                    value={picked[p.remote_address] ?? p.status}
                    onChange={(e) => setPicked((prev) => ({ ...prev, [p.remote_address]: e.target.value as 'active' | 'planned' }))}
                  >
                    <option value="active">Active</option>
                    <option value="planned">Planned</option>
                  </select>
                </td>
              </tr>
            );
          })}
        </tbody>
      </DataTable>
      {errors.peerings && <div className="form-error">{errors.peerings}</div>}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 'var(--space-2)', marginTop: 'var(--space-3)' }}>
        <ModalActions
          onClose={onClose}
          primaryLabel={`Record ${chosen.length} peering${chosen.length === 1 ? '' : 's'}`}
          primaryBusy={accept.isPending}
          primaryBusyLabel="Recording…"
          onPrimary={() => void submit()}
        />
      </div>
    </>
  );
}
