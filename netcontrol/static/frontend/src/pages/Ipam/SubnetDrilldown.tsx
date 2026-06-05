import { FormEvent, useState } from 'react';

import { useDialogs } from '@/components/DialogProvider-context';
import {
  type IpamSubnetDetail,
  useCreateIpamAllocation,
  useCreateIpamReservation,
  useDeleteIpamAllocation,
  useDeleteIpamReservation,
} from '@/api/ipam';

interface Props {
  subnet: string;
  detail: IpamSubnetDetail | undefined;
  isLoading: boolean;
  onRefresh: () => void;
}

export function SubnetDrilldown({ subnet, detail, isLoading, onRefresh }: Props) {
  if (isLoading) {
    return (
      <div className="text-muted">
        Loading subnet allocations and reservation data...
      </div>
    );
  }
  if (!detail) {
    return (
      <p className="text-muted" style={{ margin: 0 }}>
        No drilldown data available for the selected subnet.
      </p>
    );
  }

  const summary = detail.summary ?? {};
  const reservations = detail.reservations ?? [];
  const allocations = detail.allocations ?? [];
  const cloudResources = detail.cloud_resources ?? [];
  const externalPrefixes = detail.external_prefixes ?? [];
  const availablePreview = detail.available_preview ?? [];

  return (
    <div style={{ display: 'grid', gap: '1rem' }}>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          gap: '0.75rem',
          alignItems: 'flex-start',
          flexWrap: 'wrap',
        }}
      >
        <div>
          <div style={{ fontSize: '1rem', fontWeight: 700 }}>
            {detail.subnet || subnet}
          </div>
          <div className="text-muted" style={{ fontSize: '0.9em' }}>
            {summary.total_addresses ?? 0} total addresses ·{' '}
            {summary.usable_address_count ?? 0} usable
          </div>
        </div>
        <button type="button" className="btn btn-secondary" onClick={onRefresh}>
          Refresh Detail
        </button>
      </div>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
          gap: '0.75rem',
        }}
      >
        <StatCard label="Available" value={summary.available_address_count ?? 0} />
        <StatCard label="Allocated" value={summary.allocated_address_count ?? 0} />
        <StatCard label="Reserved" value={summary.reserved_address_count ?? 0} />
        <StatCard label="Utilized" value={`${summary.utilization_pct ?? 0}%`} />
      </div>

      <div>
        <div style={{ fontWeight: 600, marginBottom: '0.45rem' }}>
          Available Address Preview
        </div>
        <div className="text-muted" style={{ lineHeight: 1.5 }}>
          {availablePreview.length
            ? availablePreview.join(', ')
            : 'Preview unavailable for this subnet size.'}
        </div>
      </div>

      <ReservationsSection
        subnet={subnet}
        reservations={reservations}
        onChanged={onRefresh}
      />

      <AllocationsSection
        subnet={subnet}
        allocations={allocations}
        onChanged={onRefresh}
      />

      {(externalPrefixes.length > 0 || cloudResources.length > 0) && (
        <div style={{ display: 'grid', gap: '0.75rem' }}>
          {externalPrefixes.length > 0 && (
            <div>
              <div style={{ fontWeight: 600, marginBottom: '0.45rem' }}>
                External Prefix Context
              </div>
              <div
                className="text-muted"
                style={{ display: 'grid', gap: '0.35rem', lineHeight: 1.45 }}
              >
                {externalPrefixes.map((item, i) => (
                  <div key={i}>
                    {item.source_name || item.provider || 'External IPAM'}:{' '}
                    {item.description || item.status || 'Tracked prefix'}
                  </div>
                ))}
              </div>
            </div>
          )}
          {cloudResources.length > 0 && (
            <div>
              <div style={{ fontWeight: 600, marginBottom: '0.45rem' }}>
                Cloud Resources
              </div>
              <div
                className="text-muted"
                style={{ display: 'grid', gap: '0.35rem', lineHeight: 1.45 }}
              >
                {cloudResources.map((item, i) => (
                  <div key={i}>
                    {item.provider || 'cloud'}:{' '}
                    {item.name || item.resource_type || 'resource'}
                    {item.account_name ? ` (${item.account_name})` : ''}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="stat-card">
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

interface ReservationsSectionProps {
  subnet: string;
  reservations: NonNullable<IpamSubnetDetail['reservations']>;
  onChanged: () => void;
}

function ReservationsSection({
  subnet,
  reservations,
  onChanged,
}: ReservationsSectionProps) {
  const { confirm, alert } = useDialogs();
  const create = useCreateIpamReservation();
  const remove = useDeleteIpamReservation();
  const [showForm, setShowForm] = useState(false);
  const [startIp, setStartIp] = useState('');
  const [endIp, setEndIp] = useState('');
  const [reason, setReason] = useState('');

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!startIp.trim()) {
      void alert('Start IP is required.');
      return;
    }
    try {
      await create.mutateAsync({
        subnet,
        payload: {
          start_ip: startIp.trim(),
          end_ip: endIp.trim() || null,
          reason: reason.trim() || 'Reserved range',
        },
      });
      setStartIp('');
      setEndIp('');
      setReason('');
      onChanged();
    } catch (err) {
      void alert({ message: (err as Error).message, variant: 'error' });
    }
  };

  const handleDelete = async (id: number) => {
    if (!(await confirm('Delete this reserved range?'))) return;
    remove.mutate(id, {
      onSuccess: () => onChanged(),
      onError: (e) => {
        void alert({ message: (e as Error).message, variant: 'error' });
      },
    });
  };

  return (
    <div>
      <div style={{ fontWeight: 600, marginBottom: '0.45rem' }}>Reserved Ranges</div>
      {reservations.length ? (
        reservations.map((item) => (
          <div
            key={item.id}
            style={{
              padding: '0.5rem 0',
              borderBottom: '1px solid rgba(255,255,255,0.08)',
            }}
          >
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                gap: '0.75rem',
                flexWrap: 'wrap',
                alignItems: 'flex-start',
              }}
            >
              <div>
                <strong>{item.start_ip || ''}</strong>
                <span className="text-muted"> to {item.end_ip || ''}</span>
              </div>
              <div
                style={{
                  display: 'flex',
                  gap: '0.5rem',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                }}
              >
                <span
                  className={`badge ${
                    item.kind === 'custom' ? 'badge-warning' : 'badge-secondary'
                  }`}
                >
                  {item.kind || 'reserved'}
                </span>
                {item.kind === 'custom' && (
                  <button
                    type="button"
                    className="btn btn-secondary"
                    style={{ padding: '0.2rem 0.55rem', fontSize: '0.8em' }}
                    onClick={() => handleDelete(item.id)}
                  >
                    Delete
                  </button>
                )}
              </div>
            </div>
            <div
              className="text-muted"
              style={{ fontSize: '0.9em', lineHeight: 1.45 }}
            >
              {item.address_count ?? 0} addresses · {item.reason || 'Reserved range'}
            </div>
          </div>
        ))
      ) : (
        <p className="text-muted" style={{ margin: 0 }}>
          No reserved ranges recorded for this subnet.
        </p>
      )}

      {showForm ? (
        <form
          onSubmit={submit}
          style={{ display: 'grid', gap: '0.6rem', marginTop: '0.65rem' }}
        >
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: '1fr 1fr',
              gap: '0.5rem',
            }}
          >
            <div>
              <label className="form-label">Start IP</label>
              <input
                className="form-input"
                value={startIp}
                onChange={(e) => setStartIp(e.target.value)}
                required
                placeholder="10.0.0.10"
              />
            </div>
            <div>
              <label className="form-label">
                End IP <span className="text-muted">(optional)</span>
              </label>
              <input
                className="form-input"
                value={endIp}
                onChange={(e) => setEndIp(e.target.value)}
                placeholder="10.0.0.20"
              />
            </div>
          </div>
          <div>
            <label className="form-label">Reason</label>
            <input
              className="form-input"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              maxLength={255}
              placeholder="Reserved range"
            />
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={create.isPending}
            >
              {create.isPending ? 'Saving…' : 'Reserve'}
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setShowForm(false)}
            >
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <button
          type="button"
          className="btn btn-secondary"
          style={{ marginTop: '0.5rem', fontSize: '0.85em' }}
          onClick={() => setShowForm(true)}
        >
          + Add Reservation
        </button>
      )}
    </div>
  );
}

interface AllocationsSectionProps {
  subnet: string;
  allocations: NonNullable<IpamSubnetDetail['allocations']>;
  onChanged: () => void;
}

function AllocationsSection({
  subnet,
  allocations,
  onChanged,
}: AllocationsSectionProps) {
  const { confirm, alert } = useDialogs();
  const create = useCreateIpamAllocation();
  const remove = useDeleteIpamAllocation();
  const [showForm, setShowForm] = useState(false);
  const [address, setAddress] = useState('');
  const [hostname, setHostname] = useState('');
  const [description, setDescription] = useState('');

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!address.trim()) {
      void alert('IP address is required.');
      return;
    }
    try {
      await create.mutateAsync({
        subnet,
        payload: {
          address: address.trim(),
          hostname: hostname.trim(),
          description: description.trim(),
        },
      });
      setAddress('');
      setHostname('');
      setDescription('');
      onChanged();
    } catch (err) {
      void alert({ message: (err as Error).message, variant: 'error' });
    }
  };

  const handleDelete = async (id: number) => {
    if (!(await confirm('Remove this local allocation?'))) return;
    remove.mutate(id, {
      onSuccess: () => onChanged(),
      onError: (e) => {
        void alert({ message: (e as Error).message, variant: 'error' });
      },
    });
  };

  return (
    <div>
      <div style={{ fontWeight: 600, marginBottom: '0.45rem' }}>Allocations</div>
      {allocations.length ? (
        <div
          style={{ display: 'grid', gap: '0.5rem', maxHeight: 360, overflow: 'auto' }}
        >
          {allocations.map((item, i) => (
            <div
              key={`${item.allocation_id ?? i}-${item.ip_address}`}
              style={{
                padding: '0.6rem 0.7rem',
                border: '1px solid rgba(255,255,255,0.08)',
                borderRadius: 10,
              }}
            >
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  gap: '0.75rem',
                  alignItems: 'flex-start',
                  flexWrap: 'wrap',
                }}
              >
                <div>
                  <div style={{ fontWeight: 600 }}>{item.ip_address || ''}</div>
                  <div
                    className="text-muted"
                    style={{ fontSize: '0.9em', lineHeight: 1.45 }}
                  >
                    {item.hostname ||
                      item.dns_name ||
                      item.source_name ||
                      'Allocation'}
                    {item.group_name ? ` · ${item.group_name}` : ''}
                    {item.description ? ` · ${item.description}` : ''}
                  </div>
                </div>
                <div
                  style={{
                    display: 'flex',
                    gap: '0.35rem',
                    flexWrap: 'wrap',
                    justifyContent: 'flex-end',
                    alignItems: 'center',
                  }}
                >
                  <span
                    className={`badge ${
                      item.source_type === 'local'
                        ? 'badge-success'
                        : 'badge-secondary'
                    }`}
                  >
                    {item.source_type || 'allocation'}
                  </span>
                  {item.status && (
                    <span className="badge badge-secondary">{item.status}</span>
                  )}
                  {item.is_duplicate && (
                    <span className="badge badge-danger">Duplicate</span>
                  )}
                  {item.is_reserved && (
                    <span className="badge badge-warning">Reserved</span>
                  )}
                  {item.source_type === 'local' && item.allocation_id && (
                    <button
                      type="button"
                      className="btn btn-secondary"
                      style={{
                        padding: '0.15rem 0.45rem',
                        fontSize: '0.78em',
                        color: 'var(--danger-color)',
                      }}
                      title="Remove local allocation"
                      onClick={() => handleDelete(item.allocation_id!)}
                    >
                      ✕
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <p className="text-muted" style={{ margin: 0 }}>
          No allocations tracked for this subnet.
        </p>
      )}
      {showForm ? (
        <form
          onSubmit={submit}
          style={{ display: 'grid', gap: '0.6rem', marginTop: '0.65rem' }}
        >
          <div>
            <label className="form-label">IP Address</label>
            <input
              className="form-input"
              value={address}
              onChange={(e) => setAddress(e.target.value)}
              required
              placeholder="10.0.0.50"
            />
          </div>
          <div>
            <label className="form-label">
              Hostname / Label <span className="text-muted">(optional)</span>
            </label>
            <input
              className="form-input"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              maxLength={255}
              placeholder="e.g. printer-floor2"
            />
          </div>
          <div>
            <label className="form-label">
              Description <span className="text-muted">(optional)</span>
            </label>
            <input
              className="form-input"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              maxLength={255}
              placeholder="e.g. Managed by IT"
            />
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={create.isPending}
            >
              {create.isPending ? 'Saving…' : 'Add Allocation'}
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setShowForm(false)}
            >
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <button
          type="button"
          className="btn btn-secondary"
          style={{ marginTop: '0.5rem', fontSize: '0.85em' }}
          onClick={() => setShowForm(true)}
        >
          + Add IP Allocation
        </button>
      )}
    </div>
  );
}
