import { useState } from 'react';

import { type RoutingInstance, useDeleteRoutingInstance, useRoutingInstance, useRoutingInstances } from '@/api/routing';
import { CardHeader, CatalogueBody, Dash, RowActions } from '@/components/CatalogueParts';
import { ChangelogPanel } from '@/components/ChangelogPanel';
import { DataTable } from '@/components/DataTable';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { clickableProps } from '@/lib/clickable';
import { INSTANCE_STATUSES, formatAsn, parseAsn, statusLabel } from '@/lib/routing';
import { usePendingKeys } from '@/lib/usePendingKeys';
import { DETAIL_STACK_STYLE } from '@/lib/wideDetail';
import { DetailSection, SplitLayout } from '@/pages/Ipam/NetworkObjectParts';

import { RoutingInstanceModal } from './RoutingModals';
import { HostSelect, RoutingStatusBadge, SearchBox } from './RoutingParts';
import { useCanWriteRouting, useDeferredSearch } from './routingHooks';

const RIGHT = { textAlign: 'right' } as const;

/** The Routing page's Routing instances tab. */
export function InstancesTab() {
  const canWrite = useCanWriteRouting();
  const [searchText, setSearchText] = useState('');
  const search = useDeferredSearch(searchText);
  const [hostId, setHostId] = useState<number | null>(null);
  const [status, setStatus] = useState('');
  const [asn, setAsn] = useState('');
  const asnValue = parseAsn(asn);
  const filter = { search, host_id: hostId, status, asn: asnValue === null ? '' : String(asnValue) };
  const q = useRoutingInstances(filter);
  const remove = useDeleteRoutingInstance();
  const { confirm, alert } = useDialogs();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<RoutingInstance | 'new' | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const rows = q.data ?? [];
  const filtered = !!(search || hostId || status || asnValue !== null);

  const addButton = canWrite && (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      Add instance
    </button>
  );

  const handleDelete = (i: RoutingInstance) =>
    void deleting.run(i.id, async () => {
      const agreed = await confirm({
        title: 'Delete routing instance',
        message: `Delete routing instance "${i.name}" of ${i.hostname}? Its ${i.peering_count} peerings and ${i.peer_group_count} peer groups are deleted with it.`,
        confirmLabel: 'Delete instance',
      });
      if (!agreed) return;
      try {
        await remove.mutateAsync(i.id);
        if (selectedId === i.id) setSelectedId(null);
      } catch (err) {
        await alert({ title: 'Instance not deleted', message: `${(err as Error).message} Try again.`, variant: 'error' });
      }
    });

  const list = (
    <>
      <CardHeader
        title="Routing instances"
        sub={q.data && `${rows.length.toLocaleString()} instance${rows.length === 1 ? '' : 's'}`}
        actions={rows.length > 0 && addButton}
      />
      <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap', marginBottom: 'var(--space-3)' }}>
        <SearchBox value={searchText} onChange={setSearchText} label="Search routing instances" placeholder="Name, device, description" />
        <div style={{ minWidth: 180 }}>
          <HostSelect id="routing-instances-host" value={hostId} onChange={setHostId} allowNone noneLabel="All devices" />
        </div>
        <select className="form-select form-select-sm" aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value)} style={{ width: 'auto' }}>
          <option value="">All statuses</option>
          {INSTANCE_STATUSES.map((s) => (
            <option key={s} value={s}>
              {statusLabel(s)}
            </option>
          ))}
        </select>
        <input className="form-input form-input-sm" aria-label="Local ASN" placeholder="ASN" value={asn} onChange={(e) => setAsn(e.target.value)} style={{ width: 110 }} />
      </div>
      <CatalogueBody
        query={q}
        what="routing instances"
        rows={rows}
        empty={
          <EmptyState
            compact
            message={filtered ? 'No routing instance matches the filters.' : 'No routing instances yet.'}
            description={filtered ? undefined : 'A routing instance is a BGP process of a device: its local AS, router ID and VRF.'}
            action={filtered ? undefined : addButton || undefined}
          />
        }
      >
        <DataTable compact aria-label="Routing instances">
          <thead>
            <tr>
              <th>Device</th>
              <th>Name</th>
              <th>Local AS</th>
              <th>VRF</th>
              <th>Router ID</th>
              <th>Status</th>
              <th style={RIGHT}>Peerings</th>
              {canWrite && <th style={RIGHT}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((i) => {
              const selected = i.id === selectedId;
              return (
                <tr
                  key={i.id}
                  className={`row-clickable${selected ? ' row-selected' : ''}`}
                  aria-current={selected ? 'true' : undefined}
                  title="Show the instance's details"
                  {...clickableProps(() => setSelectedId(i.id), { role: null })}
                >
                  <td>{i.hostname}</td>
                  <td style={{ fontWeight: 600 }}>{i.name}</td>
                  <td>{formatAsn(i.asn)}</td>
                  <td>{i.vrf_name || <Dash />}</td>
                  <td>{i.router_id || <Dash />}</td>
                  <td>
                    <RoutingStatusBadge status={i.status} />
                  </td>
                  <td style={RIGHT}>{i.peering_count.toLocaleString()}</td>
                  {canWrite && (
                    <td style={RIGHT} onClick={(e) => e.stopPropagation()}>
                      <RowActions label={`routing instance ${i.name} of ${i.hostname}`} onEdit={() => setEditing(i)} onDelete={() => handleDelete(i)} deleting={deleting.isPending(i.id)} />
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {editing && <RoutingInstanceModal record={editing === 'new' ? null : editing} hostId={hostId} onClose={() => setEditing(null)} />}
    </>
  );

  return <SplitLayout list={list} detail={<InstanceDetailPanel id={selectedId} />} />;
}

export function InstanceDetailPanel({ id }: { id: number | null }) {
  const q = useRoutingInstance(id);
  if (id === null) {
    return (
      <>
        <h3 style={{ margin: '0 0 0.75rem' }}>Instance details</h3>
        <p className="text-muted" style={{ margin: 0 }}>
          Select a routing instance to see its peer groups, peerings and change history.
        </p>
      </>
    );
  }
  if (q.isError && !q.data) return <QueryError what="instance details" query={q} />;
  if (q.isPending) return <LoadingState text="Loading instance details…" />;
  const i = q.data;
  return (
    <div style={DETAIL_STACK_STYLE}>
      <div>
        <h3 style={{ margin: 0 }}>
          {i.hostname} · {i.name}
        </h3>
        <div className="text-muted" style={{ fontSize: '0.9em' }}>
          {[formatAsn(i.asn), i.router_id && `Router ID ${i.router_id}`, i.vrf_name ? `VRF ${i.vrf_name}` : 'Global', i.description].filter(Boolean).join(' · ')}
        </div>
      </div>
      <DetailSection title="Peer groups" count={i.peer_groups.length} empty="No peer groups.">
        <DataTable compact aria-label={`Peer groups of ${i.name}`} maxHeight={200}>
          <thead>
            <tr>
              <th>Name</th>
              <th>Remote AS</th>
              <th style={RIGHT}>Peerings</th>
            </tr>
          </thead>
          <tbody>
            {i.peer_groups.map((g) => (
              <tr key={g.id}>
                <td>{g.name}</td>
                <td>{formatAsn(g.remote_asn)}</td>
                <td style={RIGHT}>{g.peering_count}</td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      </DetailSection>
      <DetailSection title="Peerings" count={i.peerings.length} empty="No peerings.">
        <DataTable compact aria-label={`Peerings of ${i.name}`} maxHeight={260}>
          <thead>
            <tr>
              <th>Remote</th>
              <th>Remote AS</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {i.peerings.map((p) => (
              <tr key={p.id}>
                <td>{p.remote_address}</td>
                <td>{formatAsn(p.remote_asn)}</td>
                <td>
                  <RoutingStatusBadge status={p.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      </DetailSection>
      <ChangelogPanel objectType="routing_instance" objectId={i.id} pageSize={10} />
    </div>
  );
}
