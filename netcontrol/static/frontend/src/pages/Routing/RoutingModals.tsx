import { useId, useState } from 'react';

import { useVrfs } from '@/api/networkObjects';
import {
  type AutonomousSystem,
  type BgpPeerGroup,
  type BgpPeering,
  type InstanceStatus,
  type PeeringStatus,
  type RoutingInstance,
  useBgpPeerGroups,
  useCreateAutonomousSystem,
  useCreatePeerGroup,
  useCreatePeering,
  useCreateRoutingInstance,
  useRoutingInstances,
  useUpdateAutonomousSystem,
  useUpdatePeerGroup,
  useUpdatePeering,
  useUpdateRoutingInstance,
} from '@/api/routing';
import { DescriptionInput, SaveFailure } from '@/components/CatalogueParts';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { runSave } from '@/lib/recordSave';
import {
  ADDRESS_FAMILIES,
  ASN_MAX,
  INSTANCE_STATUSES,
  PEERING_STATUSES,
  POLICY_MAX,
  ROUTING_NAME_MAX,
  formatAsn,
  parseAsn,
  peeringAddressErrors,
  routerIdError,
  statusLabel,
} from '@/lib/routing';
import { serverFieldErrors } from '@/lib/serverFieldErrors';

import { AsSelect, Field, HostSelect } from './RoutingParts';

type Errors = Record<string, string | undefined>;

/** Field errors: the form's own first, then the server's (cleared as a field changes). */
function useServerErrors() {
  const [server, setServer] = useState<Record<string, string>>({});
  const clear = (key: string) => setServer((prev) => (prev[key] ? { ...prev, [key]: '' } : prev));
  const handle = (err: unknown) => {
    const fields = serverFieldErrors(err);
    setServer(fields);
    return Object.keys(fields).length > 0;
  };
  return { server, clear, handle, reset: () => setServer({}) };
}

function TextInput({
  id,
  value,
  onChange,
  max,
  placeholder,
  invalid,
  autoFocus,
}: {
  id: string;
  value: string;
  onChange: (v: string) => void;
  max: number;
  placeholder?: string;
  invalid?: boolean;
  autoFocus?: boolean;
}) {
  return (
    <input
      id={id}
      className="form-input"
      value={value}
      maxLength={max + 1}
      placeholder={placeholder}
      spellCheck={false}
      autoFocus={autoFocus}
      aria-invalid={invalid}
      aria-describedby={`${id}-error`}
      onChange={(e) => onChange(e.target.value)}
    />
  );
}

const tooLong = (v: string, label: string, max: number) => (v.trim().length > max ? `${label} must be at most ${max} characters.` : undefined);

// ── Autonomous system ──────────────────────────────────────────────────────

/** Creates an AS, or edits one's description, RIR and comments (the number cannot change). */
export function AutonomousSystemModal({ record, onClose }: { record: AutonomousSystem | null; onClose: () => void }) {
  const id = useId();
  const create = useCreateAutonomousSystem();
  const update = useUpdateAutonomousSystem();
  const errs = useServerErrors();
  const [asnText, setAsnText] = useState('');
  const [touched, setTouched] = useState(false);
  const [description, setDescription] = useState(record?.description ?? '');
  const [rir, setRir] = useState(record?.rir ?? '');
  const [comments, setComments] = useState(record?.comments ?? '');
  const [failure, setFailure] = useState<string | null>(null);

  const asn = parseAsn(asnText);
  const local: Errors = {
    asn: record ? undefined : asn === null ? `ASN must be a number from 1 to ${ASN_MAX} (asplain or asdot).` : undefined,
    rir: tooLong(rir, 'RIR', 64),
  };
  const error = (k: string) => (k === 'asn' && !touched ? undefined : local[k]) || errs.server[k] || undefined;

  const submit = () => {
    setTouched(true);
    if (Object.values(local).some(Boolean)) return;
    errs.reset();
    const data = { description: description.trim(), rir: rir.trim(), comments: comments.trim() };
    void runSave(
      () => (record ? update.mutateAsync({ id: record.id, data }) : create.mutateAsync({ asn: asn as number, ...data })),
      null,
      setFailure,
      onClose,
      errs.handle,
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="small"
      title={record ? `Edit ${formatAsn(record.asn)}` : 'Add autonomous system'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={record ? 'Save AS' : 'Add AS'}
          primaryBusy={create.isPending || update.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what="autonomous system" message={failure} />
      {record ? (
        <div className="form-group">
          <div className="form-label">ASN</div>
          <div>{formatAsn(record.asn)}</div>
          <div className="form-help">The number of an AS cannot change.</div>
        </div>
      ) : (
        <Field id={`${id}-asn`} label="ASN" error={error('asn')} help="For example 65001 or 1.10 (asdot). Each number is recorded once.">
          <input
            id={`${id}-asn`}
            className="form-input"
            value={asnText}
            inputMode="numeric"
            placeholder="65001"
            autoFocus
            aria-invalid={!!error('asn')}
            aria-describedby={`${id}-asn-error`}
            onChange={(e) => {
              setAsnText(e.target.value);
              errs.clear('asn');
            }}
            onBlur={() => setTouched(true)}
          />
        </Field>
      )}
      <DescriptionInput id={id} value={description} error={errs.server.description} onChange={(v) => { setDescription(v); errs.clear('description'); }} />
      <Field id={`${id}-rir`} label="RIR (optional)" error={error('rir')}>
        <TextInput id={`${id}-rir`} value={rir} max={64} placeholder="private" onChange={(v) => { setRir(v); errs.clear('rir'); }} invalid={!!error('rir')} />
      </Field>
      <Field id={`${id}-comments`} label="Comments (optional)" error={errs.server.comments}>
        <textarea id={`${id}-comments`} className="form-input" rows={3} maxLength={2000} value={comments} onChange={(e) => setComments(e.target.value)} />
      </Field>
    </Modal>
  );
}

// ── Routing instance ───────────────────────────────────────────────────────

/** Creates a routing instance of a device, or edits one (the device cannot change). */
export function RoutingInstanceModal({
  record,
  hostId,
  onClose,
}: {
  record: RoutingInstance | null;
  /** Preselects the device of a new instance. */
  hostId?: number | null;
  onClose: () => void;
}) {
  const id = useId();
  const create = useCreateRoutingInstance();
  const update = useUpdateRoutingInstance();
  const vrfs = useVrfs();
  const errs = useServerErrors();
  const [host, setHost] = useState<number | null>(record?.host_id ?? hostId ?? null);
  const [name, setName] = useState(record?.name ?? 'default');
  const [asId, setAsId] = useState<number | null>(record?.autonomous_system_id ?? null);
  const [vrfId, setVrfId] = useState<number | null>(record?.vrf_id ?? null);
  const [routerId, setRouterId] = useState(record?.router_id ?? '');
  const [status, setStatus] = useState<InstanceStatus>(record?.status ?? 'active');
  const [description, setDescription] = useState(record?.description ?? '');
  const [tried, setTried] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  const local: Errors = {
    host_id: !record && host === null ? 'Choose the device.' : undefined,
    name: !name.trim() ? 'Name is required.' : tooLong(name, 'Name', ROUTING_NAME_MAX),
    autonomous_system_id: asId === null ? 'Choose the local autonomous system.' : undefined,
    router_id: routerIdError(routerId),
  };
  const error = (k: string) => (tried || k === 'router_id' ? local[k] : undefined) || errs.server[k] || undefined;

  const submit = () => {
    setTried(true);
    if (Object.values(local).some(Boolean)) return;
    errs.reset();
    const data = {
      name: name.trim(),
      autonomous_system_id: asId,
      vrf_id: vrfId,
      router_id: routerId.trim(),
      status,
      description: description.trim(),
    };
    void runSave(
      () => (record ? update.mutateAsync({ id: record.id, data }) : create.mutateAsync({ host_id: host as number, ...data })),
      null,
      setFailure,
      onClose,
      errs.handle,
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={record ? `Edit routing instance ${record.name}` : 'Add routing instance'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={record ? 'Save instance' : 'Add instance'}
          primaryBusy={create.isPending || update.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what="routing instance" message={failure} />
      {record ? (
        <div className="form-group">
          <div className="form-label">Device</div>
          <div>{record.hostname}</div>
        </div>
      ) : (
        <Field id={`${id}-host`} label="Device" error={error('host_id')}>
          <HostSelect id={`${id}-host`} value={host} onChange={(v) => { setHost(v); errs.clear('host_id'); }} invalid={!!error('host_id')} />
        </Field>
      )}
      <Field id={`${id}-name`} label="Name" error={error('name')} help={`"default", or the name of a VRF-specific instance. Unique per device, ignoring case.`}>
        <TextInput id={`${id}-name`} value={name} max={ROUTING_NAME_MAX} autoFocus onChange={(v) => { setName(v); errs.clear('name'); }} invalid={!!error('name')} />
      </Field>
      <Field id={`${id}-as`} label="Local AS" error={error('autonomous_system_id')}>
        <AsSelect id={`${id}-as`} value={asId} onChange={(v) => { setAsId(v); errs.clear('autonomous_system_id'); }} invalid={!!error('autonomous_system_id')} />
      </Field>
      <Field id={`${id}-vrf`} label="VRF (optional)" error={errs.server.vrf_id}>
        <select id={`${id}-vrf`} className="form-select" value={vrfId ?? ''} onChange={(e) => setVrfId(e.target.value ? Number(e.target.value) : null)}>
          <option value="">Global</option>
          {(vrfs.data ?? []).map((v) => (
            <option key={v.id} value={v.id}>
              {v.name}
            </option>
          ))}
        </select>
      </Field>
      <Field id={`${id}-rid`} label="Router ID (optional)" error={error('router_id')}>
        <TextInput id={`${id}-rid`} value={routerId} max={15} placeholder="192.0.2.1" onChange={(v) => { setRouterId(v); errs.clear('router_id'); }} invalid={!!error('router_id')} />
      </Field>
      <Field id={`${id}-status`} label="Status" error={errs.server.status}>
        <select id={`${id}-status`} className="form-select" value={status} onChange={(e) => setStatus(e.target.value as InstanceStatus)}>
          {INSTANCE_STATUSES.map((s) => (
            <option key={s} value={s}>
              {statusLabel(s)}
            </option>
          ))}
        </select>
      </Field>
      <DescriptionInput id={id} value={description} error={errs.server.description} onChange={setDescription} />
    </Modal>
  );
}

function InstanceSelect({ id, value, onChange, invalid }: { id: string; value: number | null; onChange: (v: number | null) => void; invalid?: boolean }) {
  const q = useRoutingInstances();
  return (
    <select
      id={id}
      className="form-select"
      value={value ?? ''}
      aria-invalid={invalid}
      aria-describedby={`${id}-error`}
      disabled={q.isPending}
      onChange={(e) => onChange(e.target.value ? Number(e.target.value) : null)}
    >
      <option value="">{q.isPending ? 'Loading…' : 'Choose a routing instance'}</option>
      {(q.data ?? []).map((i) => (
        <option key={i.id} value={i.id}>
          {i.hostname} · {i.name} ({formatAsn(i.asn)})
        </option>
      ))}
    </select>
  );
}

function PolicyFields({
  id,
  importPolicy,
  exportPolicy,
  setImport,
  setExport,
  errors,
}: {
  id: string;
  importPolicy: string;
  exportPolicy: string;
  setImport: (v: string) => void;
  setExport: (v: string) => void;
  errors: Record<string, string>;
}) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0 var(--space-3)' }}>
      <Field id={`${id}-import`} label="Import policy (optional)" error={tooLong(importPolicy, 'Import policy', POLICY_MAX) || errors.import_policy}>
        <TextInput id={`${id}-import`} value={importPolicy} max={POLICY_MAX} placeholder="RM-IN" onChange={setImport} />
      </Field>
      <Field id={`${id}-export`} label="Export policy (optional)" error={tooLong(exportPolicy, 'Export policy', POLICY_MAX) || errors.export_policy}>
        <TextInput id={`${id}-export`} value={exportPolicy} max={POLICY_MAX} placeholder="RM-OUT" onChange={setExport} />
      </Field>
    </div>
  );
}

// ── Peer group ─────────────────────────────────────────────────────────────

export function PeerGroupModal({ record, onClose }: { record: BgpPeerGroup | null; onClose: () => void }) {
  const id = useId();
  const create = useCreatePeerGroup();
  const update = useUpdatePeerGroup();
  const errs = useServerErrors();
  const [instance, setInstance] = useState<number | null>(record?.routing_instance_id ?? null);
  const [name, setName] = useState(record?.name ?? '');
  const [remoteAs, setRemoteAs] = useState<number | null>(record?.remote_asn_id ?? null);
  const [importPolicy, setImport] = useState(record?.import_policy ?? '');
  const [exportPolicy, setExport] = useState(record?.export_policy ?? '');
  const [description, setDescription] = useState(record?.description ?? '');
  const [tried, setTried] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  const local: Errors = {
    routing_instance_id: !record && instance === null ? 'Choose the routing instance.' : undefined,
    name: !name.trim() ? 'Name is required.' : tooLong(name, 'Name', ROUTING_NAME_MAX),
  };
  const error = (k: string) => (tried ? local[k] : undefined) || errs.server[k] || undefined;

  const submit = () => {
    setTried(true);
    if (Object.values(local).some(Boolean) || tooLong(importPolicy, '', POLICY_MAX) || tooLong(exportPolicy, '', POLICY_MAX)) return;
    errs.reset();
    const data = {
      name: name.trim(),
      remote_asn_id: remoteAs,
      import_policy: importPolicy.trim(),
      export_policy: exportPolicy.trim(),
      description: description.trim(),
    };
    void runSave(
      () => (record ? update.mutateAsync({ id: record.id, data }) : create.mutateAsync({ routing_instance_id: instance as number, ...data })),
      null,
      setFailure,
      onClose,
      errs.handle,
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={record ? `Edit peer group ${record.name}` : 'Add peer group'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={record ? 'Save peer group' : 'Add peer group'}
          primaryBusy={create.isPending || update.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what="peer group" message={failure} />
      {record ? (
        <div className="form-group">
          <div className="form-label">Routing instance</div>
          <div>
            {record.hostname} · {record.routing_instance_name}
          </div>
        </div>
      ) : (
        <Field id={`${id}-instance`} label="Routing instance" error={error('routing_instance_id')}>
          <InstanceSelect id={`${id}-instance`} value={instance} onChange={setInstance} invalid={!!error('routing_instance_id')} />
        </Field>
      )}
      <Field id={`${id}-name`} label="Name" error={error('name')} help="Unique per routing instance, ignoring case.">
        <TextInput id={`${id}-name`} value={name} max={ROUTING_NAME_MAX} autoFocus onChange={(v) => { setName(v); errs.clear('name'); }} invalid={!!error('name')} />
      </Field>
      <Field id={`${id}-as`} label="Remote AS (optional)" error={errs.server.remote_asn_id}>
        <AsSelect id={`${id}-as`} value={remoteAs} onChange={setRemoteAs} allowNone />
      </Field>
      <PolicyFields id={id} importPolicy={importPolicy} exportPolicy={exportPolicy} setImport={setImport} setExport={setExport} errors={errs.server} />
      <DescriptionInput id={id} value={description} error={errs.server.description} onChange={setDescription} />
    </Modal>
  );
}

// ── Peering ────────────────────────────────────────────────────────────────

export function PeeringModal({
  record,
  instanceId,
  onClose,
}: {
  record: BgpPeering | null;
  /** Preselects the routing instance of a new peering. */
  instanceId?: number | null;
  onClose: () => void;
}) {
  const id = useId();
  const create = useCreatePeering();
  const update = useUpdatePeering();
  const errs = useServerErrors();
  const [instance, setInstance] = useState<number | null>(record?.routing_instance_id ?? instanceId ?? null);
  const groups = useBgpPeerGroups({});
  const [groupId, setGroupId] = useState<number | null>(record?.peer_group_id ?? null);
  const [localAddress, setLocal] = useState(record?.local_address ?? '');
  const [remoteAddress, setRemote] = useState(record?.remote_address ?? '');
  const [remoteAs, setRemoteAs] = useState<number | null>(record?.remote_asn_id ?? null);
  const [remoteHost, setRemoteHost] = useState<number | null>(record?.remote_host_id ?? null);
  const [status, setStatus] = useState<PeeringStatus>(record?.status ?? 'active');
  const [families, setFamilies] = useState<string[]>(record?.address_families ?? ['ipv4-unicast']);
  const [importPolicy, setImport] = useState(record?.import_policy ?? '');
  const [exportPolicy, setExport] = useState(record?.export_policy ?? '');
  const [description, setDescription] = useState(record?.description ?? '');
  const [touched, setTouched] = useState<Record<string, boolean>>({});
  const [tried, setTried] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  const addr = peeringAddressErrors(localAddress, remoteAddress);
  const local: Errors = {
    routing_instance_id: !record && instance === null ? 'Choose the routing instance.' : undefined,
    remote_address: addr.remote,
    local_address: addr.local,
    remote_asn_id: remoteAs === null ? 'Choose the remote autonomous system.' : undefined,
  };
  const error = (k: string) => (tried || touched[k] ? local[k] : undefined) || errs.server[k] || undefined;
  const instanceGroups = (groups.data ?? []).filter((g) => g.routing_instance_id === instance);

  const toggleFamily = (family: string) =>
    setFamilies((prev) => (prev.includes(family) ? prev.filter((f) => f !== family) : [...prev, family]));

  const submit = () => {
    setTried(true);
    if (Object.values(local).some(Boolean) || tooLong(importPolicy, '', POLICY_MAX) || tooLong(exportPolicy, '', POLICY_MAX)) return;
    errs.reset();
    const data = {
      peer_group_id: groupId,
      local_address: localAddress.trim(),
      remote_address: remoteAddress.trim(),
      remote_asn_id: remoteAs,
      remote_host_id: remoteHost,
      status,
      address_families: ADDRESS_FAMILIES.filter((f) => families.includes(f)),
      import_policy: importPolicy.trim(),
      export_policy: exportPolicy.trim(),
      description: description.trim(),
    };
    void runSave(
      () => (record ? update.mutateAsync({ id: record.id, data }) : create.mutateAsync({ routing_instance_id: instance as number, ...data })),
      null,
      setFailure,
      onClose,
      errs.handle,
    );
  };
  const blur = (k: string) => () => setTouched((prev) => ({ ...prev, [k]: true }));

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="medium"
      title={record ? `Edit peering with ${record.remote_address}` : 'Add BGP peering'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={record ? 'Save peering' : 'Add peering'}
          primaryBusy={create.isPending || update.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what="peering" message={failure} />
      {record ? (
        <div className="form-group">
          <div className="form-label">Routing instance</div>
          <div>
            {record.hostname} · {record.routing_instance_name} ({formatAsn(record.local_asn)})
          </div>
        </div>
      ) : (
        <Field id={`${id}-instance`} label="Routing instance" error={error('routing_instance_id')}>
          <InstanceSelect
            id={`${id}-instance`}
            value={instance}
            onChange={(v) => {
              setInstance(v);
              setGroupId(null);
            }}
            invalid={!!error('routing_instance_id')}
          />
        </Field>
      )}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0 var(--space-3)' }}>
        <Field id={`${id}-remote`} label="Remote address" error={error('remote_address')}>
          <span onBlur={blur('remote_address')}>
            <TextInput id={`${id}-remote`} value={remoteAddress} max={45} placeholder="192.0.2.2" autoFocus onChange={(v) => { setRemote(v); errs.clear('remote_address'); }} invalid={!!error('remote_address')} />
          </span>
        </Field>
        <Field id={`${id}-local`} label="Local address (optional)" error={error('local_address')}>
          <span onBlur={blur('local_address')}>
            <TextInput id={`${id}-local`} value={localAddress} max={45} placeholder="192.0.2.1" onChange={(v) => { setLocal(v); errs.clear('local_address'); }} invalid={!!error('local_address')} />
          </span>
        </Field>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0 var(--space-3)' }}>
        <Field id={`${id}-as`} label="Remote AS" error={error('remote_asn_id')}>
          <AsSelect id={`${id}-as`} value={remoteAs} onChange={(v) => { setRemoteAs(v); errs.clear('remote_asn_id'); }} invalid={!!error('remote_asn_id')} />
        </Field>
        <Field id={`${id}-status`} label="Status" error={errs.server.status}>
          <select id={`${id}-status`} className="form-select" value={status} onChange={(e) => setStatus(e.target.value as PeeringStatus)}>
            {PEERING_STATUSES.map((s) => (
              <option key={s} value={s}>
                {statusLabel(s)}
              </option>
            ))}
          </select>
        </Field>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0 var(--space-3)' }}>
        <Field id={`${id}-group`} label="Peer group (optional)" error={errs.server.peer_group_id}>
          <select id={`${id}-group`} className="form-select" value={groupId ?? ''} onChange={(e) => setGroupId(e.target.value ? Number(e.target.value) : null)}>
            <option value="">None</option>
            {instanceGroups.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </select>
        </Field>
        <Field id={`${id}-peer-host`} label="Peer device (optional)" error={errs.server.remote_host_id} help="When the peer is a Plexus device.">
          <HostSelect id={`${id}-peer-host`} value={remoteHost} onChange={setRemoteHost} allowNone />
        </Field>
      </div>
      <fieldset className="form-group" style={{ border: 0, padding: 0, margin: 0 }}>
        <legend className="form-label">Address families</legend>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-1) var(--space-3)' }}>
          {ADDRESS_FAMILIES.map((f) => (
            <label key={f} style={{ display: 'inline-flex', gap: '0.35rem', alignItems: 'center', fontSize: '0.9em' }}>
              <input type="checkbox" checked={families.includes(f)} onChange={() => toggleFamily(f)} />
              {f}
            </label>
          ))}
        </div>
        <FieldError>{errs.server.address_families}</FieldError>
      </fieldset>
      <PolicyFields id={id} importPolicy={importPolicy} exportPolicy={exportPolicy} setImport={setImport} setExport={setExport} errors={errs.server} />
      <DescriptionInput id={id} value={description} error={errs.server.description} onChange={setDescription} />
    </Modal>
  );
}
