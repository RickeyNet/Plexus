import { useState } from 'react';

import { CustomDataError } from '@/api/customData';
import { type AutonomousSystem, useAutonomousSystem, useAutonomousSystems, useDeleteAutonomousSystem } from '@/api/routing';
import { CardHeader, CatalogueBody, Dash, RowActions } from '@/components/CatalogueParts';
import { ChangelogPanel } from '@/components/ChangelogPanel';
import { DataTable } from '@/components/DataTable';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { clickableProps } from '@/lib/clickable';
import { formatAsn } from '@/lib/routing';
import { usePendingKeys } from '@/lib/usePendingKeys';
import { DETAIL_STACK_STYLE } from '@/lib/wideDetail';
import { DetailSection, SplitLayout } from '@/pages/Ipam/NetworkObjectParts';

import { AutonomousSystemModal } from './RoutingModals';
import { RoutingStatusBadge, SearchBox } from './RoutingParts';
import { useCanWriteRouting, useDeferredSearch } from './routingHooks';

const RIGHT = { textAlign: 'right' } as const;

/** The Routing page's Autonomous systems tab: the AS records and the selected one's instances and peerings. */
export function AutonomousSystemsTab() {
  const canWrite = useCanWriteRouting();
  const [searchText, setSearchText] = useState('');
  const search = useDeferredSearch(searchText);
  const q = useAutonomousSystems(search);
  const remove = useDeleteAutonomousSystem();
  const { confirm, alert } = useDialogs();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<AutonomousSystem | 'new' | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const rows = q.data ?? [];

  const addButton = canWrite && (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      Add AS
    </button>
  );

  const handleDelete = (a: AutonomousSystem) =>
    void deleting.run(a.id, async () => {
      const agreed = await confirm({
        title: 'Delete autonomous system',
        message: `Delete ${formatAsn(a.asn)}? This cannot be undone.`,
        confirmLabel: 'Delete AS',
      });
      if (!agreed) return;
      try {
        await remove.mutateAsync(a.id);
        if (selectedId === a.id) setSelectedId(null);
      } catch (err) {
        const inUse = err instanceof CustomDataError && err.status === 409;
        await alert({
          title: inUse ? 'AS in use' : 'AS not deleted',
          message: inUse ? (err as Error).message : `${formatAsn(a.asn)} was not deleted: ${(err as Error).message} Try again.`,
          variant: 'error',
        });
      }
    });

  const list = (
    <>
      <CardHeader
        title="Autonomous systems"
        sub={q.data && `${rows.length.toLocaleString()} AS${rows.length === 1 ? '' : 'es'}`}
        actions={
          <>
            <SearchBox value={searchText} onChange={setSearchText} label="Search autonomous systems" placeholder="ASN, description, RIR" />
            {rows.length > 0 && addButton}
          </>
        }
      />
      <CatalogueBody
        query={q}
        what="autonomous systems"
        rows={rows}
        empty={
          <EmptyState
            compact
            message={search ? 'No AS matches the search.' : 'No autonomous systems yet.'}
            description={search ? undefined : 'Add the AS numbers your devices use and peer with, or accept suggestions from observed BGP neighbors on the Compliance tab.'}
            action={search ? undefined : addButton || undefined}
          />
        }
      >
        <DataTable compact aria-label="Autonomous systems">
          <thead>
            <tr>
              <th>ASN</th>
              <th>Description</th>
              <th>Tenant</th>
              <th>RIR</th>
              <th style={RIGHT}>Instances</th>
              <th style={RIGHT}>Peerings</th>
              {canWrite && <th style={RIGHT}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => {
              const selected = a.id === selectedId;
              return (
                <tr
                  key={a.id}
                  className={`row-clickable${selected ? ' row-selected' : ''}`}
                  aria-current={selected ? 'true' : undefined}
                  title="Show the AS's details"
                  {...clickableProps(() => setSelectedId(a.id), { role: null })}
                >
                  <td style={{ fontWeight: 600 }}>{formatAsn(a.asn)}</td>
                  <td>{a.description || <Dash />}</td>
                  <td>{a.tenant_name || <Dash />}</td>
                  <td>{a.rir || <Dash />}</td>
                  <td style={RIGHT}>{a.instance_count.toLocaleString()}</td>
                  <td style={RIGHT}>{a.peering_count.toLocaleString()}</td>
                  {canWrite && (
                    <td style={RIGHT} onClick={(e) => e.stopPropagation()}>
                      <RowActions label={formatAsn(a.asn)} onEdit={() => setEditing(a)} onDelete={() => handleDelete(a)} deleting={deleting.isPending(a.id)} />
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {editing && <AutonomousSystemModal record={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </>
  );

  return <SplitLayout list={list} detail={<AutonomousSystemDetailPanel id={selectedId} />} />;
}

export function AutonomousSystemDetailPanel({ id }: { id: number | null }) {
  const q = useAutonomousSystem(id);
  if (id === null) {
    return (
      <>
        <h3 style={{ margin: '0 0 0.75rem' }}>AS details</h3>
        <p className="text-muted" style={{ margin: 0 }}>
          Select an AS to see the routing instances and peerings that use it, and its change history.
        </p>
      </>
    );
  }
  if (q.isError && !q.data) return <QueryError what="AS details" query={q} />;
  if (q.isPending) return <LoadingState text="Loading AS details…" />;
  const a = q.data;
  return (
    <div style={DETAIL_STACK_STYLE}>
      <div>
        <h3 style={{ margin: 0 }}>{formatAsn(a.asn)}</h3>
        <div className="text-muted" style={{ fontSize: '0.9em' }}>
          {[a.description, a.tenant_name && `Tenant ${a.tenant_name}`, a.rir && `RIR ${a.rir}`].filter(Boolean).join(' · ') || 'No description'}
        </div>
        {a.comments && <p style={{ margin: '0.5rem 0 0', whiteSpace: 'pre-wrap' }}>{a.comments}</p>}
      </div>
      <DetailSection title="Routing instances (local AS)" count={a.routing_instances.length} empty="No routing instance uses this AS.">
        <DataTable compact aria-label={`Routing instances of ${formatAsn(a.asn)}`} maxHeight={240}>
          <thead>
            <tr>
              <th>Device</th>
              <th>Instance</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {a.routing_instances.map((i) => (
              <tr key={i.id}>
                <td>{i.hostname}</td>
                <td>{i.name}</td>
                <td>
                  <RoutingStatusBadge status={i.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      </DetailSection>
      <DetailSection title="Peerings" count={a.peerings.length} empty="No peering names this AS.">
        <DataTable compact aria-label={`Peerings with ${formatAsn(a.asn)}`} maxHeight={240}>
          <thead>
            <tr>
              <th>Device</th>
              <th>Remote</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {a.peerings.map((p) => (
              <tr key={p.id}>
                <td>{p.hostname}</td>
                <td>
                  {p.remote_address} ({formatAsn(p.remote_asn)})
                </td>
                <td>
                  <RoutingStatusBadge status={p.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      </DetailSection>
      <ChangelogPanel objectType="autonomous_system" objectId={a.id} pageSize={10} />
    </div>
  );
}
