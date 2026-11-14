import { FormEvent, type ReactNode, useId, useMemo, useState } from 'react';

import { useAuthStatus } from '@/api/auth';
import {
  type CustomField,
  type ObjectRef,
  useCustomFields,
  useObjectData,
  useSaveObjectData,
} from '@/api/customData';
import { Callout } from '@/components/Callout';
import { CustomDataSection } from '@/components/CustomDataSection';
import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
import { FieldError } from '@/components/FieldError';
import {
  type IpamSubnetDetail,
  useCreateIpamAllocation,
  useCreateIpamReservation,
  useDeleteIpamAllocation,
  useDeleteIpamReservation,
} from '@/api/ipam';
import type { InterfaceAddress } from '@/api/networkObjects';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { TagChips } from '@/components/TagChips';
import { applicableFields, formatCustomValue } from '@/lib/customData';
import { formatCount } from '@/lib/formatCount';
import { addressRoleLabel, describeCarriers, formatInterfaceAddress, interfacesByAddress } from '@/lib/networkObjects';
import { saveCustomDataDraft, useCustomDataDraft } from '@/lib/useCustomDataDraft';
import { StatGrid, StatTile } from '@/components/StatTile';

/** Inline form buttons: Cancel then the primary action, right-aligned like a modal footer. */
const FORM_ACTIONS_STYLE = {
  display: 'flex',
  justifyContent: 'flex-end',
  gap: 'var(--space-2)',
} as const;

interface Props {
  subnet: string;
  /** The subnet's VRF ('' for none); with the subnet it names the prefix's tags and fields. */
  vrf?: string | null;
  detail: IpamSubnetDetail | undefined;
  isLoading: boolean;
  /** Shown in place of the drilldown when the detail request failed with nothing cached. */
  loadError: ReactNode;
  onRefresh: () => void;
}

export function SubnetDrilldown({ subnet, vrf, detail, isLoading, loadError, onRefresh }: Props) {
  if (loadError) return loadError;
  if (isLoading) {
    return (
      <LoadingState text="Loading subnet allocations and reservation data…" />
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
  const interfaces = detail.interfaces ?? [];

  return (
    <div style={{ display: 'grid', gap: '1rem' }}>
      <div>
        <div style={{ fontSize: '1rem', fontWeight: 700 }}>
          {detail.subnet || subnet}
        </div>
        <div className="text-muted" style={{ fontSize: '0.9em' }}>
          {formatCount(summary.total_addresses)} total addresses ·{' '}
          {formatCount(summary.usable_address_count)} usable
        </div>
      </div>
      <StatGrid compact minTileWidth={120}>
        <StatTile label="Available" value={formatCount(summary.available_address_count)} />
        <StatTile label="Allocated" value={formatCount(summary.allocated_address_count)} />
        <StatTile label="Reserved" value={formatCount(summary.reserved_address_count)} />
        <StatTile label="Utilized" value={`${summary.utilization_pct ?? 0}%`} />
      </StatGrid>

      <CustomDataPanel key={`${subnet}|${vrf ?? ''}`} subnet={subnet} vrf={vrf ?? ''} />

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
        interfaces={interfaces}
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

/** A stored value as text, URLs as links. */
function FieldValue({ field, value }: { field: CustomField; value: string | number | boolean }) {
  const text = formatCustomValue(field, value);
  if (field.field_type === 'url') {
    return (
      <a href={text} target="_blank" rel="noopener noreferrer" style={{ overflowWrap: 'anywhere' }}>
        {text}
      </a>
    );
  }
  return <span style={{ overflowWrap: 'anywhere' }}>{text}</span>;
}

/**
 * The prefix's tags and custom field values: read-only for everyone, with
 * an Edit button for admins (prefix writes are admin-only, like every other
 * IPAM write).
 */
function CustomDataPanel({ subnet, vrf }: { subnet: string; vrf: string }) {
  const isAdmin = useAuthStatus().data?.role === 'admin';
  const ref: ObjectRef = { type: 'prefix', subnet, vrf };
  const dataQ = useObjectData(ref);
  const fieldsQ = useCustomFields('prefix');
  const [editing, setEditing] = useState(false);

  const fields = applicableFields(fieldsQ.data ?? [], 'prefix');
  const stored = dataQ.data?.fields ?? {};
  const shownFields = fields.filter((f) => stored[f.key] !== undefined && stored[f.key] !== '');
  const tags = dataQ.data?.tags ?? [];
  const editButton = isAdmin && !editing && (
    <button
      type="button"
      className="btn btn-secondary btn-sm"
      aria-label="Edit tags and custom fields"
      onClick={() => setEditing(true)}
    >
      Edit
    </button>
  );

  let body;
  if (editing) {
    body = <CustomDataEditor prefixRef={ref} onDone={() => setEditing(false)} />;
  } else if (dataQ.isError && !dataQ.data) {
    body = <QueryError what="tags and custom fields" query={dataQ} />;
  } else if (dataQ.isPending) {
    body = <LoadingState text="Loading tags and custom fields…" />;
  } else if (tags.length === 0 && shownFields.length === 0) {
    body = (
      <EmptyState
        compact
        message="No tags or custom fields set."
        description={isAdmin ? undefined : 'An admin can add them.'}
        action={editButton || undefined}
      />
    );
  } else {
    body = (
      <div style={{ display: 'grid', gap: '0.35rem', lineHeight: 1.45 }}>
        {tags.length > 0 && <TagChips tags={tags} />}
        {shownFields.map((field) => (
          <div key={field.id}>
            <span className="text-muted">{field.label}: </span>
            <FieldValue field={field} value={stored[field.key]} />
          </div>
        ))}
      </div>
    );
  }

  const showHeaderButton = editButton && (tags.length > 0 || shownFields.length > 0);
  return (
    <div>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '0.5rem',
          marginBottom: '0.45rem',
        }}
      >
        <div style={{ fontWeight: 600 }}>Tags and Custom Fields</div>
        {showHeaderButton && editButton}
      </div>
      {body}
    </div>
  );
}

function CustomDataEditor({ prefixRef, onDone }: { prefixRef: ObjectRef; onDone: () => void }) {
  const draft = useCustomDataDraft('prefix', prefixRef);
  const save = useSaveObjectData();
  const [saveError, setSaveError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSaveError(null);
    if (!draft.ready || Object.keys(draft.checkRequired()).length > 0) return;
    const failure = await saveCustomDataDraft(save, draft, prefixRef);
    if (failure) setSaveError(`The tags and custom fields were not saved: ${failure} Fix them and save again.`);
    else onDone();
  };

  return (
    <form onSubmit={submit} style={{ display: 'grid', gap: '0.6rem' }}>
      {saveError && <Callout tone="danger">{saveError}</Callout>}
      <CustomDataSection objectType="prefix" draft={draft} canCreateTags title={null} />
      <div style={FORM_ACTIONS_STYLE}>
        <button type="button" className="btn btn-secondary btn-sm" onClick={onDone}>
          Cancel
        </button>
        <button type="submit" className="btn btn-primary btn-sm" disabled={save.isPending || !draft.ready}>
          {save.isPending ? 'Saving…' : 'Save'}
        </button>
      </div>
    </form>
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
  const fid = useId();
  const { confirm, alert } = useDialogs();
  const create = useCreateIpamReservation();
  const remove = useDeleteIpamReservation();
  const [showForm, setShowForm] = useState(false);
  const [startIp, setStartIp] = useState('');
  const [endIp, setEndIp] = useState('');
  const [reason, setReason] = useState('');
  const [startIpError, setStartIpError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSaveError(null);
    if (!startIp.trim()) {
      setStartIpError('Start IP is required.');
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
      setSaveError((err as Error).message);
    }
  };

  const handleDelete = async (item: NonNullable<IpamSubnetDetail['reservations']>[number]) => {
    if (
      !(await confirm({
        title: 'Delete reserved range',
        message: `Delete reserved range ${item.start_ip || ''} to ${item.end_ip || ''}?`,
        confirmLabel: 'Delete',
      }))
    )
      return;
    remove.mutate(item.id, {
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
              borderBottom: '1px solid var(--border)',
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
                  <DeleteButton
                    size="xs"
                    aria-label={`Delete reservation ${item.start_ip || ''}`.trim()}
                    onClick={() => handleDelete(item)}
                  />
                )}
              </div>
            </div>
            <div
              className="text-muted"
              style={{ fontSize: '0.9em', lineHeight: 1.45 }}
            >
              {formatCount(item.address_count)} addresses · {item.reason || 'Reserved range'}
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
          {saveError && <Callout tone="danger">{saveError}</Callout>}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: '1fr 1fr',
              gap: '0.5rem',
            }}
          >
            <div>
              <label className="form-label" htmlFor={`${fid}-start-ip`}>Start IP</label>
              <input
                id={`${fid}-start-ip`}
                className="form-input"
                value={startIp}
                onChange={(e) => {
                  setStartIp(e.target.value);
                  setStartIpError(null);
                }}
                required
                placeholder="10.0.0.10"
                aria-invalid={!!startIpError}
              />
              <FieldError>{startIpError}</FieldError>
            </div>
            <div>
              <label className="form-label" htmlFor={`${fid}-end-ip`}>
                End IP <span className="text-muted">(optional)</span>
              </label>
              <input
                id={`${fid}-end-ip`}
                className="form-input"
                value={endIp}
                onChange={(e) => setEndIp(e.target.value)}
                placeholder="10.0.0.20"
              />
            </div>
          </div>
          <div>
            <label className="form-label" htmlFor={`${fid}-reason`}>Reason</label>
            <input
              id={`${fid}-reason`}
              className="form-input"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              maxLength={255}
              placeholder="Reserved range"
            />
          </div>
          <div style={FORM_ACTIONS_STYLE}>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => setShowForm(false)}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary btn-sm"
              disabled={create.isPending}
            >
              {create.isPending ? 'Saving…' : 'Reserve'}
            </button>
          </div>
        </form>
      ) : (
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          style={{ marginTop: '0.5rem' }}
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
  /** Addresses device interfaces carry in the subnet: shown on the matching rows. */
  interfaces: InterfaceAddress[];
  onChanged: () => void;
}

function AllocationsSection({
  subnet,
  allocations,
  interfaces,
  onChanged,
}: AllocationsSectionProps) {
  const fid = useId();
  const carriers = useMemo(() => interfacesByAddress(interfaces), [interfaces]);
  const allocated = new Set(allocations.map((a) => a.ip_address ?? ''));
  const untracked = interfaces.filter((i) => !allocated.has(i.address));
  const { confirm, alert } = useDialogs();
  const create = useCreateIpamAllocation();
  const remove = useDeleteIpamAllocation();
  const [showForm, setShowForm] = useState(false);
  const [address, setAddress] = useState('');
  const [hostname, setHostname] = useState('');
  const [description, setDescription] = useState('');
  const [addressError, setAddressError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSaveError(null);
    if (!address.trim()) {
      setAddressError('IP address is required.');
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
      setSaveError((err as Error).message);
    }
  };

  const handleDelete = async (id: number, ip: string | undefined) => {
    if (
      !(await confirm({
        title: 'Remove local allocation',
        message: `Remove local allocation ${ip || ''}?`,
        confirmLabel: 'Remove',
      }))
    )
      return;
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
                border: '1px solid var(--border)',
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
                  {carriers.has(item.ip_address ?? '') && (
                    <div className="text-muted" style={{ fontSize: '0.85em', lineHeight: 1.45 }}>
                      On {describeCarriers(carriers.get(item.ip_address ?? '') ?? [])}
                    </div>
                  )}
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
                    <DeleteButton
                      size="xs"
                      label="✕"
                      title="Remove local allocation"
                      aria-label={`Remove allocation ${item.ip_address || ''}`.trim()}
                      onClick={() => handleDelete(item.allocation_id!, item.ip_address)}
                    />
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
      {untracked.length > 0 && (
        <div style={{ marginTop: '0.65rem' }}>
          <div style={{ fontWeight: 600, marginBottom: '0.35rem' }}>Interface addresses</div>
          <div className="text-muted" style={{ display: 'grid', gap: '0.25rem', lineHeight: 1.45, maxHeight: 240, overflow: 'auto' }}>
            {untracked.map((i) => (
              <div key={`${i.host_id}|${i.interface}|${i.address}`}>
                <span style={{ color: 'var(--text)', fontWeight: 600 }}>{formatInterfaceAddress(i)}</span> on{' '}
                {i.hostname} {i.interface}
                {i.role !== 'primary' ? ` · ${addressRoleLabel(i)}` : ''}
              </div>
            ))}
          </div>
        </div>
      )}
      {showForm ? (
        <form
          onSubmit={submit}
          style={{ display: 'grid', gap: '0.6rem', marginTop: '0.65rem' }}
        >
          {saveError && <Callout tone="danger">{saveError}</Callout>}
          <div>
            <label className="form-label" htmlFor={`${fid}-ip-address`}>IP Address</label>
            <input
              id={`${fid}-ip-address`}
              className="form-input"
              value={address}
              onChange={(e) => {
                setAddress(e.target.value);
                setAddressError(null);
              }}
              required
              placeholder="10.0.0.50"
              aria-invalid={!!addressError}
            />
            <FieldError>{addressError}</FieldError>
          </div>
          <div>
            <label className="form-label" htmlFor={`${fid}-hostname-label`}>
              Hostname / Label <span className="text-muted">(optional)</span>
            </label>
            <input
              id={`${fid}-hostname-label`}
              className="form-input"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              maxLength={255}
              placeholder="e.g. printer-floor2"
            />
          </div>
          <div>
            <label className="form-label" htmlFor={`${fid}-description`}>
              Description <span className="text-muted">(optional)</span>
            </label>
            <input
              id={`${fid}-description`}
              className="form-input"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              maxLength={255}
              placeholder="e.g. Managed by IT"
            />
          </div>
          <div style={FORM_ACTIONS_STYLE}>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => setShowForm(false)}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary btn-sm"
              disabled={create.isPending}
            >
              {create.isPending ? 'Saving…' : 'Add Allocation'}
            </button>
          </div>
        </form>
      ) : (
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          style={{ marginTop: '0.5rem' }}
          onClick={() => setShowForm(true)}
        >
          + Add IP Allocation
        </button>
      )}
    </div>
  );
}
