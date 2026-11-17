import { useState } from 'react';
import { Link, useSearchParams } from 'react-router';

import {
  type Cluster,
  useCluster,
  useClusters,
  useDeleteCluster,
  useRemoveClusterHost,
} from '@/api/virtualization';
import { CardHeader, CatalogueBody, Dash, RowActions } from '@/components/CatalogueParts';
import { ChangelogPanel } from '@/components/ChangelogPanel';
import { DataTable } from '@/components/DataTable';
import { DeleteButton } from '@/components/DeleteButton';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { clickableProps } from '@/lib/clickable';
import { usePendingKeys } from '@/lib/usePendingKeys';
import { DETAIL_STACK_STYLE } from '@/lib/wideDetail';
import { DetailSection, OriginBadge, SplitLayout } from '@/pages/Ipam/NetworkObjectParts';

import { AddClusterHostModal, ClusterModal, VmModal } from './VirtualizationModals';
import { useCanWriteVirtualization, useConfirmDelete } from './virtualizationHooks';
import { VmStatusBadge } from './VirtualizationParts';

const RIGHT = { textAlign: 'right' } as const;

/** The Clusters tab: the clusters, and the selected one's hosts, VMs and changes. `?cluster=<id>` selects one. */
export function ClustersTab() {
  const canWrite = useCanWriteVirtualization();
  const q = useClusters();
  const remove = useDeleteCluster();
  const confirmDelete = useConfirmDelete();
  const deleting = usePendingKeys<number>();
  const [params, setParams] = useSearchParams();
  const [editing, setEditing] = useState<Cluster | 'new' | null>(null);
  const [search, setSearch] = useState('');
  const selectedId = Number(params.get('cluster')) || null;
  const select = (id: number | null) => setParams(id === null ? {} : { cluster: String(id) }, { replace: true });
  const needle = search.trim().toLowerCase();
  const rows = (q.data ?? []).filter(
    (c) => !needle || [c.name, c.cluster_type_name, c.cluster_group_name, c.site_name].some((v) => v?.toLowerCase().includes(needle)),
  );

  const addButton = canWrite && (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      Add cluster
    </button>
  );

  const list = (
    <>
      <CardHeader
        title="Clusters"
        sub={q.data && `${q.data.length.toLocaleString()} cluster${q.data.length === 1 ? '' : 's'}`}
        actions={(q.data ?? []).length > 0 && addButton}
      />
      {(q.data ?? []).length > 0 && (
        <input
          type="search"
          className="form-input"
          placeholder="Name, type, group or site"
          aria-label="Search clusters"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ width: 240, marginBottom: '0.75rem' }}
        />
      )}
      <CatalogueBody
        query={q}
        what="clusters"
        rows={rows}
        empty={
          needle ? (
            <EmptyState compact message="No cluster matches the search." />
          ) : (
            <EmptyState
              compact
              message="No clusters yet."
              description="A cluster pools the hypervisors that run virtual machines. Add a cluster type first, then the cluster."
              action={addButton || undefined}
            />
          )
        }
      >
        <DataTable compact aria-label="Clusters">
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Group</th>
              <th>Site</th>
              <th style={RIGHT}>Hosts</th>
              <th style={RIGHT}>VMs</th>
              <th>Origin</th>
              {canWrite && <th style={RIGHT}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => {
              const selected = c.id === selectedId;
              return (
                <tr
                  key={c.id}
                  className={`row-clickable${selected ? ' row-selected' : ''}`}
                  aria-current={selected ? 'true' : undefined}
                  title="Show the cluster's details"
                  {...clickableProps(() => select(c.id), { role: null })}
                >
                  <td style={{ fontWeight: 600 }}>{c.name}</td>
                  <td>{c.cluster_type_name}</td>
                  <td>{c.cluster_group_name ?? <Dash />}</td>
                  <td>{c.site_name ?? <Dash />}</td>
                  <td style={RIGHT}>{c.host_count.toLocaleString()}</td>
                  <td style={RIGHT}>{c.vm_count.toLocaleString()}</td>
                  <td>
                    <OriginBadge origin={c.origin} />
                  </td>
                  {canWrite && (
                    <td style={RIGHT} onClick={(e) => e.stopPropagation()}>
                      <RowActions
                        label={`cluster ${c.name}`}
                        onEdit={() => setEditing(c)}
                        onDelete={() =>
                          void deleting.run(c.id, async () => {
                            if (await confirmDelete('cluster', c.name, () => remove.mutateAsync(c.id))) {
                              if (selectedId === c.id) select(null);
                            }
                          })
                        }
                        deleting={deleting.isPending(c.id)}
                      />
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {editing && <ClusterModal cluster={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </>
  );

  return <SplitLayout list={list} detail={<ClusterDetailPanel id={selectedId} />} />;
}

function ClusterDetailPanel({ id }: { id: number | null }) {
  const q = useCluster(id);
  const canWrite = useCanWriteVirtualization();
  const removeHost = useRemoveClusterHost(id ?? 0);
  const confirmDelete = useConfirmDelete();
  const removing = usePendingKeys<number>();
  const [addingHost, setAddingHost] = useState(false);
  const [addingVm, setAddingVm] = useState(false);

  if (id === null) {
    return (
      <>
        <h3 style={{ margin: '0 0 0.75rem' }}>Cluster details</h3>
        <p className="text-muted" style={{ margin: 0 }}>
          Select a cluster to see its hypervisor hosts and virtual machines.
        </p>
      </>
    );
  }
  if (q.isError && !q.data) {
    return (
      <>
        <h3 style={{ margin: '0 0 0.75rem' }}>Cluster details</h3>
        <QueryError what="cluster details" query={q} />
      </>
    );
  }
  if (q.isPending) return <LoadingState text="Loading cluster…" />;
  const c = q.data;
  return (
    <div style={DETAIL_STACK_STYLE}>
      <div>
        <h3 style={{ margin: 0 }}>{c.name}</h3>
        <div className="text-muted" style={{ fontSize: '0.9em' }}>
          {[c.cluster_type_name, c.cluster_group_name, c.site_name, c.tenant_name].filter(Boolean).join(' · ')}
          {c.description ? ` · ${c.description}` : ''}
        </div>
        {c.comments && <p style={{ margin: '0.4rem 0 0', whiteSpace: 'pre-wrap' }}>{c.comments}</p>}
      </div>
      <DetailSection title="Hypervisor hosts" count={c.hosts.length} empty="No hosts in this cluster.">
        <DataTable compact aria-label={`Hosts of ${c.name}`} maxHeight={240}>
          <thead>
            <tr>
              <th>Host</th>
              <th>Address</th>
              {canWrite && <th style={RIGHT}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {c.hosts.map((h) => (
              <tr key={h.id}>
                <td>
                  <Link to={`/devices/${h.id}`}>{h.hostname}</Link>
                </td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>{h.ip_address}</td>
                {canWrite && (
                  <td style={RIGHT}>
                    <DeleteButton
                      aria-label={`Remove host ${h.hostname} from the cluster`}
                      busy={removing.isPending(h.id)}
                      onClick={() =>
                        void removing.run(h.id, () =>
                          confirmDelete('cluster member', h.hostname, () => removeHost.mutateAsync(h.id), 'The host stays in the inventory.'),
                        )
                      }
                    />
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </DataTable>
      </DetailSection>
      <DetailSection title="Virtual machines" count={c.virtual_machines.length} empty="No virtual machines in this cluster.">
        <DataTable compact aria-label={`Virtual machines of ${c.name}`} maxHeight={320}>
          <thead>
            <tr>
              <th>Name</th>
              <th>Status</th>
              <th>Primary IP</th>
            </tr>
          </thead>
          <tbody>
            {c.virtual_machines.map((vm) => (
              <tr key={vm.id}>
                <td>{vm.name}</td>
                <td>
                  <VmStatusBadge status={vm.status} />
                </td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>{vm.primary_ip4 || vm.primary_ip6 || <Dash />}</td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      </DetailSection>
      {canWrite && (
        <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
          <button type="button" className="btn btn-sm btn-secondary" onClick={() => setAddingHost(true)}>
            Add host
          </button>
          <button type="button" className="btn btn-sm btn-secondary" onClick={() => setAddingVm(true)}>
            Add virtual machine
          </button>
        </div>
      )}
      <ChangelogPanel objectType="cluster" objectId={c.id} pageSize={10} />
      {addingHost && (
        <AddClusterHostModal clusterId={c.id} memberIds={c.hosts.map((h) => h.id)} onClose={() => setAddingHost(false)} />
      )}
      {addingVm && <VmModal vm={null} defaultClusterId={c.id} onClose={() => setAddingVm(false)} />}
    </div>
  );
}
