import { type ReactNode, useState } from 'react';
import { Link } from 'react-router';

import { useAuthStatus } from '@/api/auth';
import {
  type VirtualMachine,
  type VmFilter,
  type VmInterface,
  useClusters,
  useDeleteVirtualMachine,
  useDeleteVmInterface,
  useSyncCloudVms,
  useVirtualMachine,
  useVirtualMachines,
} from '@/api/virtualization';
import { Badge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { CardHeader, CatalogueBody, Dash, RowActions } from '@/components/CatalogueParts';
import { ChangelogPanel } from '@/components/ChangelogPanel';
import { DataTable } from '@/components/DataTable';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { ObjectDataPanel } from '@/components/ObjectDataPanel';
import { clickableProps } from '@/lib/clickable';
import { idToSelect, selectToId } from '@/lib/deviceModel';
import { usePendingKeys } from '@/lib/usePendingKeys';
import { cloudResourceLabel, formatMemory, VM_STATUSES, vmStatusLabel } from '@/lib/virtualization';
import { DETAIL_STACK_STYLE } from '@/lib/wideDetail';
import { DetailSection, OriginBadge, SplitLayout } from '@/pages/Ipam/NetworkObjectParts';

import { VmInterfaceModal, VmModal } from './VirtualizationModals';
import { useCanWriteVirtualization, useConfirmDelete } from './virtualizationHooks';
import { VmStatusBadge } from './VirtualizationParts';

const RIGHT = { textAlign: 'right' } as const;
const MONO = { fontFamily: 'var(--font-mono)' } as const;

/** The Virtual machines tab: the filtered VM list and the selected VM's details. */
export function VirtualMachinesTab() {
  const canWrite = useCanWriteVirtualization();
  const isAdmin = useAuthStatus().data?.role === 'admin';
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const [clusterId, setClusterId] = useState<number | null>(null);
  const filter: VmFilter = { search: search.trim() || undefined, status: status || undefined, cluster_id: clusterId ?? undefined };
  const q = useVirtualMachines(filter);
  const clusters = useClusters();
  const remove = useDeleteVirtualMachine();
  const sync = useSyncCloudVms();
  const { alert } = useDialogs();
  const confirmDelete = useConfirmDelete();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<VirtualMachine | 'new' | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const rows = q.data ?? [];
  const filtered = !!(filter.search || filter.status || filter.cluster_id);

  const handleSync = async () => {
    try {
      const r = await sync.mutateAsync();
      await alert({
        title: 'Cloud instances synced',
        message: `${r.accounts} cloud accounts read: ${r.created} VMs added, ${r.updated} updated, ${r.offline} set offline, ${r.kept_manual} kept as edited.${r.failed ? ` ${r.failed} accounts failed; see the server log.` : ''}`,
      });
    } catch (err) {
      await alert({ message: `The cloud instances were not synced: ${(err as Error).message} Try again.`, variant: 'error' });
    }
  };

  const addButton = canWrite && (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      Add virtual machine
    </button>
  );

  const list = (
    <>
      <CardHeader
        title="Virtual machines"
        sub={q.data && `${rows.length.toLocaleString()} virtual machine${rows.length === 1 ? '' : 's'}`}
        actions={
          <>
            {isAdmin && (
              <BusyButton className="btn btn-sm btn-secondary" busy={sync.isPending} busyLabel="Syncing…" onClick={() => void handleSync()}>
                Sync cloud instances
              </BusyButton>
            )}
            {addButton}
          </>
        }
      />
      <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
        <input
          type="search"
          className="form-input"
          placeholder="Name, platform or IP"
          aria-label="Search virtual machines"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ width: 220 }}
        />
        <select className="form-select" aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value)} style={{ width: 170 }}>
          <option value="">Any status</option>
          {VM_STATUSES.map((s) => (
            <option key={s} value={s}>
              {vmStatusLabel(s)}
            </option>
          ))}
        </select>
        <select
          className="form-select"
          aria-label="Cluster"
          value={idToSelect(clusterId)}
          onChange={(e) => setClusterId(selectToId(e.target.value))}
          style={{ width: 220 }}
        >
          <option value="">Any cluster</option>
          {(clusters.data ?? []).map((c) => (
            <option key={c.id} value={c.id}>
              {c.name}
            </option>
          ))}
        </select>
      </div>
      <CatalogueBody
        query={q}
        what="virtual machines"
        rows={rows}
        empty={
          filtered ? (
            <EmptyState compact message="No virtual machine matches these filters." />
          ) : (
            <EmptyState
              compact
              message="No virtual machines yet."
              description="Add one by hand, or let the cloud sync mirror the AWS, Azure and GCP instances Cloud Visibility discovers."
              action={addButton || undefined}
            />
          )
        }
      >
        <DataTable compact aria-label="Virtual machines">
          <thead>
            <tr>
              <th>Name</th>
              <th>Status</th>
              <th>Cluster</th>
              <th>Primary IP</th>
              <th style={RIGHT}>vCPUs</th>
              <th style={RIGHT}>Memory</th>
              <th>Origin</th>
              {canWrite && <th style={RIGHT}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((vm) => {
              const selected = vm.id === selectedId;
              return (
                <tr
                  key={vm.id}
                  className={`row-clickable${selected ? ' row-selected' : ''}`}
                  aria-current={selected ? 'true' : undefined}
                  title="Show the virtual machine's details"
                  {...clickableProps(() => setSelectedId(vm.id), { role: null })}
                >
                  <td style={{ fontWeight: 600 }}>{vm.name}</td>
                  <td>
                    <VmStatusBadge status={vm.status} />
                  </td>
                  <td>{vm.cluster_name}</td>
                  <td style={MONO}>{vm.primary_ip4 || vm.primary_ip6 || <Dash />}</td>
                  <td style={RIGHT}>{vm.vcpus ?? <Dash />}</td>
                  <td style={RIGHT}>{vm.memory_mb === null ? <Dash /> : formatMemory(vm.memory_mb)}</td>
                  <td>
                    <OriginBadge origin={vm.origin} />
                  </td>
                  {canWrite && (
                    <td style={RIGHT} onClick={(e) => e.stopPropagation()}>
                      <RowActions
                        label={`virtual machine ${vm.name}`}
                        onEdit={() => setEditing(vm)}
                        onDelete={() =>
                          void deleting.run(vm.id, async () => {
                            const note = vm.origin === 'discovered' ? 'The cloud sync adds it again while the instance exists.' : '';
                            if (await confirmDelete('virtual machine', vm.name, () => remove.mutateAsync(vm.id), note)) {
                              if (selectedId === vm.id) setSelectedId(null);
                            }
                          })
                        }
                        deleting={deleting.isPending(vm.id)}
                      />
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {editing && <VmModal vm={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </>
  );

  return <SplitLayout list={list} detail={<VmDetailPanel id={selectedId} />} />;
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-muted">{label}</dt>
      <dd style={{ margin: 0 }}>{children}</dd>
    </>
  );
}

export function VmDetailPanel({ id }: { id: number | null }) {
  const q = useVirtualMachine(id);
  const canWrite = useCanWriteVirtualization();
  const [editing, setEditing] = useState<VmInterface | 'new' | null>(null);
  const removeInterface = useDeleteVmInterface(id ?? 0);
  const confirmDelete = useConfirmDelete();
  const deleting = usePendingKeys<number>();

  if (id === null) {
    return (
      <>
        <h3 style={{ margin: '0 0 0.75rem' }}>Virtual machine details</h3>
        <p className="text-muted" style={{ margin: 0 }}>
          Select a virtual machine to see its interfaces, addresses and changes.
        </p>
      </>
    );
  }
  if (q.isError && !q.data) {
    return (
      <>
        <h3 style={{ margin: '0 0 0.75rem' }}>Virtual machine details</h3>
        <QueryError what="virtual machine details" query={q} />
      </>
    );
  }
  if (q.isPending) return <LoadingState text="Loading virtual machine…" />;
  const vm = q.data;
  const cloud = cloudResourceLabel(vm);
  return (
    <div style={DETAIL_STACK_STYLE}>
      <div>
        <h3 style={{ margin: 0 }}>{vm.name}</h3>
        <div style={{ display: 'flex', gap: '0.4rem', marginTop: '0.3rem' }}>
          <VmStatusBadge status={vm.status} />
          <OriginBadge origin={vm.origin} />
          {vm.role_name && <Badge size="sm">{vm.role_name}</Badge>}
        </div>
      </div>
      <dl style={{ display: 'grid', gridTemplateColumns: 'max-content 1fr', gap: '0.3rem 1rem', margin: 0 }}>
        <Row label="Cluster">
          <Link to={`/virtualization/clusters?cluster=${vm.cluster_id}`}>{vm.cluster_name}</Link> ({vm.cluster_type_name})
        </Row>
        <Row label="Site">{vm.site_name ?? <Dash />}</Row>
        <Row label="Tenant">{vm.tenant_name ?? <Dash />}</Row>
        <Row label="Platform">{vm.platform || <Dash />}</Row>
        <Row label="Resources">
          {[
            vm.vcpus !== null ? `${vm.vcpus} vCPU` : null,
            vm.memory_mb !== null ? formatMemory(vm.memory_mb) : null,
            vm.disk_gb !== null ? `${vm.disk_gb} GB disk` : null,
          ]
            .filter(Boolean)
            .join(' · ') || <Dash />}
        </Row>
        <Row label="Primary IPs">
          <span style={MONO}>{[vm.primary_ip4, vm.primary_ip6].filter(Boolean).join(', ') || '-'}</span>
        </Row>
        <Row label="Cloud resource">
          {cloud ? (
            <Link to="/cloud-visibility" title={vm.cloud_resource_uid}>
              {cloud}
            </Link>
          ) : vm.cloud_resource_uid ? (
            <span className="text-muted">No longer discovered ({vm.cloud_resource_uid})</span>
          ) : (
            <Dash />
          )}
        </Row>
        {vm.description && <Row label="Description">{vm.description}</Row>}
        {vm.comments && <Row label="Comments">{vm.comments}</Row>}
      </dl>
      <DetailSection title="Interfaces" count={vm.interfaces.length} empty="No interfaces recorded.">
        <DataTable compact aria-label={`Interfaces of ${vm.name}`} maxHeight={320}>
          <thead>
            <tr>
              <th>Name</th>
              <th>MAC</th>
              <th>Addresses</th>
              <th>VLAN / VRF</th>
              {canWrite && <th style={RIGHT}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {vm.interfaces.map((i) => (
              <tr key={i.id}>
                <td>
                  {i.name}
                  {!i.enabled && (
                    <Badge size="sm" style={{ marginLeft: '0.3rem' }}>
                      Disabled
                    </Badge>
                  )}
                </td>
                <td style={MONO}>{i.mac_address || <Dash />}</td>
                <td style={MONO}>{i.addresses.length ? i.addresses.join(', ') : <Dash />}</td>
                <td>
                  {[i.untagged_vlan_vid !== null ? `VLAN ${i.untagged_vlan_vid}` : null, i.vrf_name ? `VRF ${i.vrf_name}` : null]
                    .filter(Boolean)
                    .join(' · ') || <Dash />}
                </td>
                {canWrite && (
                  <td style={RIGHT}>
                    <RowActions
                      label={`interface ${i.name}`}
                      onEdit={() => setEditing(i)}
                      onDelete={() =>
                        void deleting.run(i.id, () => confirmDelete('interface', i.name, () => removeInterface.mutateAsync(i.id)))
                      }
                      deleting={deleting.isPending(i.id)}
                    />
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </DataTable>
      </DetailSection>
      {canWrite && (
        <div>
          <button type="button" className="btn btn-sm btn-secondary" onClick={() => setEditing('new')}>
            Add interface
          </button>
        </div>
      )}
      <ChangelogPanel objectType="virtual_machine" objectId={vm.id} pageSize={10} />
      {editing && <VmInterfaceModal vmId={vm.id} iface={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
      <ObjectDataPanel objectType="virtual_machine" objectId={vm.id} />
    </div>
  );
}
