import { type ReactNode, useId, useMemo, useState } from 'react';

import { useDeviceRoles } from '@/api/deviceModel';
import { useGeoSites } from '@/api/floorPlan';
import { useInventoryGroupsFull } from '@/api/inventory';
import { useVlans, useVrfs } from '@/api/networkObjects';
import {
  type Cluster,
  type ClusterCatalogItem,
  type VirtualMachine,
  type VmInterface,
  useAddClusterHost,
  useClusterGroups,
  useClusters,
  useClusterTypes,
  useSaveCluster,
  useSaveClusterGroup,
  useSaveClusterType,
  useSaveVirtualMachine,
  useSaveVmInterface,
  useTenantChoices,
} from '@/api/virtualization';
import { DescriptionInput, SaveFailure } from '@/components/CatalogueParts';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { NameInput } from '@/components/NameInput';
import { idToSelect, selectToId } from '@/lib/deviceModel';
import { runSave } from '@/lib/recordSave';
import { serverFieldErrors } from '@/lib/serverFieldErrors';
import { useNameField } from '@/lib/useNameField';
import {
  COMMENTS_MAX,
  countToText,
  INTERFACE_NAME_MAX,
  parseAddressList,
  parseOptionalCount,
  PLATFORM_MAX,
  VM_NAME_MAX,
  VM_STATUSES,
  vmStatusLabel,
} from '@/lib/virtualization';

type Errors = Record<string, string | undefined>;

/** The server's per-field messages of a failed save; `true` when there were any (shown at the fields). */
function useServerErrors() {
  const [errors, setErrors] = useState<Errors>({});
  return {
    errors,
    clear: (key: string) => setErrors((prev) => ({ ...prev, [key]: undefined })),
    reset: () => setErrors({}),
    handle: (err: unknown) => {
      const fields = serverFieldErrors(err);
      setErrors(fields);
      return Object.keys(fields).some((k) => k !== 'name');
    },
  };
}

function Field({
  id,
  label,
  help,
  error,
  children,
}: {
  id: string;
  label: string;
  help?: string;
  error?: string;
  children: ReactNode;
}) {
  return (
    <div className="form-group">
      <label className="form-label" htmlFor={id}>
        {label}
      </label>
      {children}
      {help && <div className="form-help">{help}</div>}
      <FieldError id={`${id}-error`}>{error}</FieldError>
    </div>
  );
}

/** A `<select>` of records by id, with a "none" option when `noneLabel` is given. */
function IdSelect({
  id,
  value,
  onChange,
  options,
  noneLabel,
  invalid,
}: {
  id: string;
  value: number | null;
  onChange: (id: number | null) => void;
  options: { id: number; name: string }[];
  noneLabel?: string;
  invalid?: boolean;
}) {
  return (
    <select
      id={id}
      className="form-select"
      value={idToSelect(value)}
      aria-invalid={invalid}
      aria-describedby={`${id}-error`}
      onChange={(e) => onChange(selectToId(e.target.value))}
    >
      {noneLabel !== undefined ? <option value="">{noneLabel}</option> : value === null && <option value="">Choose…</option>}
      {options.map((o) => (
        <option key={o.id} value={o.id}>
          {o.name}
        </option>
      ))}
    </select>
  );
}

function TextArea({ id, value, onChange, max }: { id: string; value: string; onChange: (v: string) => void; max: number }) {
  return (
    <textarea id={id} className="form-input" rows={3} value={value} maxLength={max} onChange={(e) => onChange(e.target.value)} />
  );
}

// ── Cluster type / group ───────────────────────────────────────────────────

/** Creates or edits a cluster type (`kind` type) or cluster group. */
export function CatalogModal({
  kind,
  item,
  onClose,
}: {
  kind: 'type' | 'group';
  item: ClusterCatalogItem | null;
  onClose: () => void;
}) {
  const id = useId();
  const saveType = useSaveClusterType();
  const saveGroup = useSaveClusterGroup();
  const save = kind === 'type' ? saveType : saveGroup;
  const what = kind === 'type' ? 'cluster type' : 'cluster group';
  const name = useNameField(item?.name ?? '', VM_NAME_MAX, 'Name', (n) => `A ${what} named "${n}" already exists.`);
  const [description, setDescription] = useState(item?.description ?? '');
  const [failure, setFailure] = useState<string | null>(null);
  const server = useServerErrors();

  const submit = () => {
    name.touch();
    if (name.error) return;
    server.reset();
    void runSave(
      () => save.mutateAsync({ id: item?.id ?? null, data: { name: name.trimmed, description: description.trim() } }),
      name,
      setFailure,
      onClose,
      server.handle,
    );
  };

  const title = `${item ? 'Edit' : 'Add'} ${what}`;
  return (
    <Modal
      isOpen
      onClose={onClose}
      size="small"
      title={title}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={item ? `Save ${what}` : `Add ${what}`}
          primaryBusy={save.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what={what} message={failure} />
      <NameInput id={id} label="Name" field={name} max={VM_NAME_MAX} help="Unique, ignoring case." />
      <FieldError>{server.errors.name}</FieldError>
      <DescriptionInput
        id={id}
        value={description}
        error={server.errors.description}
        onChange={(v) => {
          setDescription(v);
          server.clear('description');
        }}
      />
    </Modal>
  );
}

// ── Cluster ────────────────────────────────────────────────────────────────

export function ClusterModal({ cluster, onClose }: { cluster: Cluster | null; onClose: () => void }) {
  const id = useId();
  const save = useSaveCluster();
  const types = useClusterTypes();
  const groups = useClusterGroups();
  const sites = useGeoSites();
  const tenants = useTenantChoices();
  const name = useNameField(cluster?.name ?? '', VM_NAME_MAX, 'Name', (n) => `A cluster named "${n}" already exists.`);
  const [typeId, setTypeId] = useState<number | null>(cluster?.cluster_type_id ?? null);
  const [groupId, setGroupId] = useState<number | null>(cluster?.cluster_group_id ?? null);
  const [siteId, setSiteId] = useState<number | null>(cluster?.site_id ?? null);
  const [tenantId, setTenantId] = useState<number | null>(cluster?.tenant_id ?? null);
  const [description, setDescription] = useState(cluster?.description ?? '');
  const [comments, setComments] = useState(cluster?.comments ?? '');
  const [typeTouched, setTypeTouched] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const server = useServerErrors();
  const typeError = typeTouched && typeId === null ? 'Choose a cluster type.' : server.errors.cluster_type_id;

  const submit = () => {
    name.touch();
    setTypeTouched(true);
    if (name.error || typeId === null) return;
    server.reset();
    const data = {
      name: name.trimmed,
      cluster_type_id: typeId,
      cluster_group_id: groupId,
      site_id: siteId,
      tenant_id: tenantId,
      description: description.trim(),
      comments: comments.trim(),
    };
    void runSave(() => save.mutateAsync({ id: cluster?.id ?? null, data }), name, setFailure, onClose, server.handle);
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={cluster ? `Edit cluster ${cluster.name}` : 'Add cluster'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={cluster ? 'Save cluster' : 'Add cluster'}
          primaryBusy={save.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what="cluster" message={failure} />
      <NameInput id={id} label="Name" field={name} max={VM_NAME_MAX} help="Unique, ignoring case." />
      <FieldError>{server.errors.name}</FieldError>
      <Field id={`${id}-type`} label="Cluster type" error={typeError}>
        <IdSelect
          id={`${id}-type`}
          value={typeId}
          options={types.data ?? []}
          invalid={!!typeError}
          onChange={(v) => {
            setTypeId(v);
            server.clear('cluster_type_id');
          }}
        />
      </Field>
      <Field id={`${id}-group`} label="Cluster group" error={server.errors.cluster_group_id}>
        <IdSelect id={`${id}-group`} value={groupId} options={groups.data ?? []} noneLabel="No group" onChange={setGroupId} />
      </Field>
      <Field id={`${id}-site`} label="Site" error={server.errors.site_id}>
        <IdSelect id={`${id}-site`} value={siteId} options={sites.data ?? []} noneLabel="No site" onChange={setSiteId} />
      </Field>
      <Field id={`${id}-tenant`} label="Tenant" error={server.errors.tenant_id}>
        <IdSelect id={`${id}-tenant`} value={tenantId} options={tenants.data ?? []} noneLabel="No tenant" onChange={setTenantId} />
      </Field>
      <DescriptionInput
        id={id}
        value={description}
        error={server.errors.description}
        onChange={(v) => {
          setDescription(v);
          server.clear('description');
        }}
      />
      <Field id={`${id}-comments`} label="Comments (optional)" error={server.errors.comments}>
        <TextArea id={`${id}-comments`} value={comments} onChange={setComments} max={COMMENTS_MAX} />
      </Field>
    </Modal>
  );
}

/** Adds a hypervisor host (an inventory device) to a cluster. */
export function AddClusterHostModal({
  clusterId,
  memberIds,
  onClose,
}: {
  clusterId: number;
  memberIds: number[];
  onClose: () => void;
}) {
  const id = useId();
  const groups = useInventoryGroupsFull(true);
  const add = useAddClusterHost(clusterId);
  const [hostId, setHostId] = useState<number | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const [error, setError] = useState<string | undefined>();
  const hosts = useMemo(() => {
    const members = new Set(memberIds);
    return (groups.data ?? [])
      .flatMap((g) => g.hosts ?? [])
      .filter((h) => !members.has(h.id))
      .map((h) => ({ id: h.id, name: `${h.hostname} (${h.ip_address})` }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [groups.data, memberIds]);

  const submit = () => {
    if (hostId === null) {
      setError('Choose a host.');
      return;
    }
    void runSave(() => add.mutateAsync(hostId), null, setFailure, onClose);
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="small"
      title="Add hypervisor host"
      footer={
        <ModalActions onClose={onClose} primaryLabel="Add host" primaryBusy={add.isPending} primaryBusyLabel="Adding…" onPrimary={submit} />
      }
    >
      <SaveFailure what="host" message={failure} />
      <Field id={`${id}-host`} label="Host" help="A physical hypervisor from the inventory." error={error}>
        <IdSelect
          id={`${id}-host`}
          value={hostId}
          options={hosts}
          invalid={!!error}
          onChange={(v) => {
            setHostId(v);
            setError(undefined);
          }}
        />
      </Field>
    </Modal>
  );
}

// ── Virtual machine ────────────────────────────────────────────────────────

const COUNT_FIELDS = [
  { key: 'vcpus', label: 'vCPUs', max: 4096 },
  { key: 'memory_mb', label: 'Memory (MB)', max: 64 * 1024 * 1024 },
  { key: 'disk_gb', label: 'Disk (GB)', max: 1024 * 1024 },
] as const;

type CountKey = (typeof COUNT_FIELDS)[number]['key'];

export function VmModal({
  vm,
  defaultClusterId,
  onClose,
}: {
  vm: VirtualMachine | null;
  defaultClusterId?: number | null;
  onClose: () => void;
}) {
  const id = useId();
  const save = useSaveVirtualMachine();
  const clusters = useClusters();
  const roles = useDeviceRoles();
  const tenants = useTenantChoices();
  const name = useNameField(vm?.name ?? '', VM_NAME_MAX, 'Name', (n) => `A VM named "${n}" already exists in this cluster.`);
  const [clusterId, setClusterId] = useState<number | null>(vm?.cluster_id ?? defaultClusterId ?? null);
  const [status, setStatus] = useState(vm?.status ?? 'active');
  const [roleId, setRoleId] = useState<number | null>(vm?.role_id ?? null);
  const [tenantId, setTenantId] = useState<number | null>(vm?.tenant_id ?? null);
  const [platform, setPlatform] = useState(vm?.platform ?? '');
  const [counts, setCounts] = useState<Record<CountKey, string>>({
    vcpus: countToText(vm?.vcpus),
    memory_mb: countToText(vm?.memory_mb),
    disk_gb: countToText(vm?.disk_gb),
  });
  const [ip4, setIp4] = useState(vm?.primary_ip4 ?? '');
  const [ip6, setIp6] = useState(vm?.primary_ip6 ?? '');
  const [description, setDescription] = useState(vm?.description ?? '');
  const [comments, setComments] = useState(vm?.comments ?? '');
  const [clusterTouched, setClusterTouched] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const server = useServerErrors();

  const parsed = Object.fromEntries(
    COUNT_FIELDS.map((f) => [f.key, parseOptionalCount(counts[f.key], f.max)]),
  ) as Record<CountKey, number | null | undefined>;
  const countError = (key: CountKey, max: number) =>
    parsed[key] === undefined ? `Enter a whole number from 0 to ${max.toLocaleString()}, or leave it empty.` : server.errors[key];
  const clusterError = clusterTouched && clusterId === null ? 'Choose a cluster.' : server.errors.cluster_id;

  const submit = () => {
    name.touch();
    setClusterTouched(true);
    if (name.error || clusterId === null || COUNT_FIELDS.some((f) => parsed[f.key] === undefined)) return;
    server.reset();
    const data = {
      name: name.trimmed,
      cluster_id: clusterId,
      status,
      role_id: roleId,
      tenant_id: tenantId,
      platform: platform.trim(),
      vcpus: parsed.vcpus ?? null,
      memory_mb: parsed.memory_mb ?? null,
      disk_gb: parsed.disk_gb ?? null,
      primary_ip4: ip4.trim(),
      primary_ip6: ip6.trim(),
      description: description.trim(),
      comments: comments.trim(),
    };
    void runSave(() => save.mutateAsync({ id: vm?.id ?? null, data }), name, setFailure, onClose, server.handle);
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="large"
      title={vm ? `Edit virtual machine ${vm.name}` : 'Add virtual machine'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={vm ? 'Save virtual machine' : 'Add virtual machine'}
          primaryBusy={save.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what="virtual machine" message={failure} />
      {vm?.origin === 'discovered' && (
        <div className="form-help" style={{ marginBottom: '0.75rem' }}>
          Saving makes this VM manual: the cloud sync keeps your values and no longer updates it.
        </div>
      )}
      <NameInput id={id} label="Name" field={name} max={VM_NAME_MAX} help="Unique within its cluster, ignoring case." />
      <FieldError>{server.errors.name}</FieldError>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0 1rem' }}>
        <Field id={`${id}-cluster`} label="Cluster" error={clusterError}>
          <IdSelect
            id={`${id}-cluster`}
            value={clusterId}
            options={clusters.data ?? []}
            invalid={!!clusterError}
            onChange={(v) => {
              setClusterId(v);
              server.clear('cluster_id');
            }}
          />
        </Field>
        <Field id={`${id}-status`} label="Status" error={server.errors.status}>
          <select id={`${id}-status`} className="form-select" value={status} onChange={(e) => setStatus(e.target.value)}>
            {VM_STATUSES.map((s) => (
              <option key={s} value={s}>
                {vmStatusLabel(s)}
              </option>
            ))}
          </select>
        </Field>
        <Field id={`${id}-role`} label="Role" error={server.errors.role_id}>
          <IdSelect id={`${id}-role`} value={roleId} options={roles.data ?? []} noneLabel="No role" onChange={setRoleId} />
        </Field>
        <Field id={`${id}-tenant`} label="Tenant" error={server.errors.tenant_id}>
          <IdSelect id={`${id}-tenant`} value={tenantId} options={tenants.data ?? []} noneLabel="No tenant" onChange={setTenantId} />
        </Field>
        <Field id={`${id}-platform`} label="Platform (optional)" error={server.errors.platform}>
          <input
            id={`${id}-platform`}
            className="form-input"
            value={platform}
            maxLength={PLATFORM_MAX}
            onChange={(e) => {
              setPlatform(e.target.value);
              server.clear('platform');
            }}
          />
        </Field>
        {COUNT_FIELDS.map((f) => {
          const error = countError(f.key, f.max);
          return (
            <Field key={f.key} id={`${id}-${f.key}`} label={`${f.label} (optional)`} error={error}>
              <input
                id={`${id}-${f.key}`}
                className="form-input"
                inputMode="numeric"
                value={counts[f.key]}
                aria-invalid={!!error}
                aria-describedby={`${id}-${f.key}-error`}
                onChange={(e) => {
                  setCounts((prev) => ({ ...prev, [f.key]: e.target.value }));
                  server.clear(f.key);
                }}
              />
            </Field>
          );
        })}
        <Field id={`${id}-ip4`} label="Primary IPv4 (optional)" error={server.errors.primary_ip4}>
          <input
            id={`${id}-ip4`}
            className="form-input"
            value={ip4}
            placeholder="192.0.2.10"
            spellCheck={false}
            aria-invalid={!!server.errors.primary_ip4}
            onChange={(e) => {
              setIp4(e.target.value);
              server.clear('primary_ip4');
            }}
          />
        </Field>
        <Field id={`${id}-ip6`} label="Primary IPv6 (optional)" error={server.errors.primary_ip6}>
          <input
            id={`${id}-ip6`}
            className="form-input"
            value={ip6}
            placeholder="2001:db8::10"
            spellCheck={false}
            aria-invalid={!!server.errors.primary_ip6}
            onChange={(e) => {
              setIp6(e.target.value);
              server.clear('primary_ip6');
            }}
          />
        </Field>
      </div>
      <DescriptionInput
        id={id}
        value={description}
        error={server.errors.description}
        onChange={(v) => {
          setDescription(v);
          server.clear('description');
        }}
      />
      <Field id={`${id}-comments`} label="Comments (optional)" error={server.errors.comments}>
        <TextArea id={`${id}-comments`} value={comments} onChange={setComments} max={COMMENTS_MAX} />
      </Field>
    </Modal>
  );
}

// ── VM interface ───────────────────────────────────────────────────────────

export function VmInterfaceModal({
  vmId,
  iface,
  onClose,
}: {
  vmId: number;
  iface: VmInterface | null;
  onClose: () => void;
}) {
  const id = useId();
  const save = useSaveVmInterface(vmId);
  const vlans = useVlans();
  const vrfs = useVrfs();
  const name = useNameField(iface?.name ?? '', INTERFACE_NAME_MAX, 'Name', (n) => `The VM already has an interface named "${n}".`);
  const [enabled, setEnabled] = useState(iface?.enabled ?? true);
  const [mac, setMac] = useState(iface?.mac_address ?? '');
  const [mtuText, setMtuText] = useState(countToText(iface?.mtu));
  const [mode, setMode] = useState(iface?.mode ?? '');
  const [vlanId, setVlanId] = useState<number | null>(iface?.untagged_vlan_id ?? null);
  const [vrfId, setVrfId] = useState<number | null>(iface?.vrf_id ?? null);
  const [description, setDescription] = useState(iface?.description ?? '');
  const [addresses, setAddresses] = useState((iface?.addresses ?? []).join('\n'));
  const [failure, setFailure] = useState<string | null>(null);
  const server = useServerErrors();
  const mtu = parseOptionalCount(mtuText, 65536);
  const mtuError = mtu === undefined ? 'Enter a whole number from 68 to 65536, or leave it empty.' : server.errors.mtu;

  const submit = () => {
    name.touch();
    if (name.error || mtu === undefined) return;
    server.reset();
    const data = {
      name: name.trimmed,
      enabled,
      mac_address: mac.trim(),
      mtu,
      mode,
      untagged_vlan_id: vlanId,
      vrf_id: vrfId,
      description: description.trim(),
      addresses: parseAddressList(addresses),
    };
    void runSave(() => save.mutateAsync({ id: iface?.id ?? null, data }), name, setFailure, onClose, server.handle);
  };

  const vlanOptions = (vlans.data ?? []).map((v) => ({
    id: v.id,
    name: `${v.vid}${v.name ? ` ${v.name}` : ''}${v.site ? ` (${v.site.name})` : ''}`,
  }));

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={iface ? `Edit interface ${iface.name}` : 'Add interface'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={iface ? 'Save interface' : 'Add interface'}
          primaryBusy={save.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what="interface" message={failure} />
      <NameInput id={id} label="Name" field={name} max={INTERFACE_NAME_MAX} help="Unique on the VM, ignoring case." />
      <FieldError>{server.errors.name}</FieldError>
      <div className="form-group">
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled
        </label>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0 1rem' }}>
        <Field id={`${id}-mac`} label="MAC address (optional)" error={server.errors.mac_address}>
          <input
            id={`${id}-mac`}
            className="form-input"
            value={mac}
            placeholder="00:50:56:00:00:01"
            spellCheck={false}
            aria-invalid={!!server.errors.mac_address}
            onChange={(e) => {
              setMac(e.target.value);
              server.clear('mac_address');
            }}
          />
        </Field>
        <Field id={`${id}-mtu`} label="MTU (optional)" error={mtuError}>
          <input
            id={`${id}-mtu`}
            className="form-input"
            inputMode="numeric"
            value={mtuText}
            aria-invalid={!!mtuError}
            onChange={(e) => {
              setMtuText(e.target.value);
              server.clear('mtu');
            }}
          />
        </Field>
        <Field id={`${id}-mode`} label="802.1Q mode" error={server.errors.mode}>
          <select id={`${id}-mode`} className="form-select" value={mode} onChange={(e) => setMode(e.target.value)}>
            <option value="">None</option>
            <option value="access">Access</option>
            <option value="tagged">Tagged</option>
          </select>
        </Field>
        <Field id={`${id}-vlan`} label="Untagged VLAN" error={server.errors.untagged_vlan_id}>
          <IdSelect
            id={`${id}-vlan`}
            value={vlanId}
            options={vlanOptions}
            noneLabel="No VLAN"
            invalid={!!server.errors.untagged_vlan_id}
            onChange={(v) => {
              setVlanId(v);
              server.clear('untagged_vlan_id');
            }}
          />
        </Field>
        <Field id={`${id}-vrf`} label="VRF" error={server.errors.vrf_id}>
          <IdSelect id={`${id}-vrf`} value={vrfId} options={vrfs.data ?? []} noneLabel="Global" onChange={setVrfId} />
        </Field>
      </div>
      <Field
        id={`${id}-addresses`}
        label="Addresses (optional)"
        help="One per line, in CIDR form: 192.0.2.10/24 or 2001:db8::10/64."
        error={server.errors.addresses}
      >
        <textarea
          id={`${id}-addresses`}
          className="form-input"
          rows={3}
          value={addresses}
          spellCheck={false}
          aria-invalid={!!server.errors.addresses}
          onChange={(e) => {
            setAddresses(e.target.value);
            server.clear('addresses');
          }}
        />
      </Field>
      <DescriptionInput
        id={id}
        value={description}
        error={server.errors.description}
        onChange={(v) => {
          setDescription(v);
          server.clear('description');
        }}
      />
    </Modal>
  );
}

