import { useState } from 'react';

import {
  type BgpPeerGroup,
  type BgpPeering,
  useBgpPeerGroups,
  useBgpPeering,
  useBgpPeerings,
  useDeletePeerGroup,
  useDeletePeering,
} from '@/api/routing';
import { CardHeader, CatalogueBody, Dash, RowActions } from '@/components/CatalogueParts';
import { ChangelogPanel } from '@/components/ChangelogPanel';
import { DataTable } from '@/components/DataTable';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { clickableProps } from '@/lib/clickable';
import { PEERING_STATUSES, formatAsn, parseAsn, statusLabel } from '@/lib/routing';
import { usePendingKeys } from '@/lib/usePendingKeys';
import { DETAIL_STACK_STYLE } from '@/lib/wideDetail';
import { SplitLayout } from '@/pages/Ipam/NetworkObjectParts';

import { PeerGroupModal, PeeringModal } from './RoutingModals';
import { HostSelect, RoutingStatusBadge, SearchBox } from './RoutingParts';
import { useCanWriteRouting, useDeferredSearch } from './routingHooks';

const RIGHT = { textAlign: 'right' } as const;

type Selection = { kind: 'peering'; id: number } | { kind: 'group'; id: number } | null;

/** The Routing page's BGP peerings tab: the peerings and, under them, the peer groups. */
export function PeeringsTab() {
  const canWrite = useCanWriteRouting();
  const [searchText, setSearchText] = useState('');
  const search = useDeferredSearch(searchText);
  const [hostId, setHostId] = useState<number | null>(null);
  const [status, setStatus] = useState('');
  const [asnText, setAsnText] = useState('');
  const asn = parseAsn(asnText);
  const q = useBgpPeerings({ search, host_id: hostId, status, asn: asn === null ? '' : String(asn) });
  const groupsQ = useBgpPeerGroups({ host_id: hostId, search });
  const removePeering = useDeletePeering();
  const removeGroup = useDeletePeerGroup();
  const { confirm, alert } = useDialogs();
  const deleting = usePendingKeys<string>();
  const [editingPeering, setEditingPeering] = useState<BgpPeering | 'new' | null>(null);
  const [editingGroup, setEditingGroup] = useState<BgpPeerGroup | 'new' | null>(null);
  const [selected, setSelected] = useState<Selection>(null);
  const rows = q.data ?? [];
  const groups = groupsQ.data ?? [];
  const filtered = !!(search || hostId || status || asn !== null);

  const remove = async (key: string, title: string, message: string, label: string, run: () => Promise<unknown>) =>
    deleting.run(key, async () => {
      if (!(await confirm({ title, message, confirmLabel: label }))) return;
      try {
        await run();
        setSelected(null);
      } catch (err) {
        await alert({ title: `${title.replace('Delete ', '')} not deleted`, message: `${(err as Error).message} Try again.`, variant: 'error' });
      }
    });

  const addPeering = canWrite && (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditingPeering('new')}>
      Add peering
    </button>
  );
  const addGroup = canWrite && (
    <button type="button" className="btn btn-sm btn-secondary" onClick={() => setEditingGroup('new')}>
      Add peer group
    </button>
  );

  const list = (
    <>
      <CardHeader
        title="BGP peerings"
        sub={q.data && `${rows.length.toLocaleString()} peering${rows.length === 1 ? '' : 's'}`}
        actions={
          <>
            {addGroup}
            {rows.length > 0 && addPeering}
          </>
        }
      />
      <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap', marginBottom: 'var(--space-3)' }}>
        <SearchBox value={searchText} onChange={setSearchText} label="Search peerings" placeholder="Address, device, peer group" />
        <div style={{ minWidth: 180 }}>
          <HostSelect id="routing-peerings-host" value={hostId} onChange={setHostId} allowNone noneLabel="All devices" />
        </div>
        <select className="form-select form-select-sm" aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value)} style={{ width: 'auto' }}>
          <option value="">All statuses</option>
          {PEERING_STATUSES.map((s) => (
            <option key={s} value={s}>
              {statusLabel(s)}
            </option>
          ))}
        </select>
        <input
          className="form-input form-input-sm"
          aria-label="Local or remote ASN"
          placeholder="ASN"
          value={asnText}
          onChange={(e) => setAsnText(e.target.value)}
          title="Shows the peerings whose local or remote AS is this number."
          style={{ width: 110 }}
        />
      </div>
      <CatalogueBody
        query={q}
        what="BGP peerings"
        rows={rows}
        empty={
          <EmptyState
            compact
            message={filtered ? 'No peering matches the filters.' : 'No BGP peerings yet.'}
            description={filtered ? undefined : 'A peering is one intended BGP session of a routing instance. Add an instance first.'}
            action={filtered ? undefined : addPeering || undefined}
          />
        }
      >
        <DataTable compact aria-label="BGP peerings">
          <thead>
            <tr>
              <th>Device</th>
              <th>Instance</th>
              <th>Remote</th>
              <th>Remote AS</th>
              <th>Peer group</th>
              <th>Families</th>
              <th>Status</th>
              {canWrite && <th style={RIGHT}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((p) => {
              const isSelected = selected?.kind === 'peering' && selected.id === p.id;
              return (
                <tr
                  key={p.id}
                  className={`row-clickable${isSelected ? ' row-selected' : ''}`}
                  aria-current={isSelected ? 'true' : undefined}
                  title="Show the peering's details"
                  {...clickableProps(() => setSelected({ kind: 'peering', id: p.id }), { role: null })}
                >
                  <td>{p.hostname}</td>
                  <td>{p.routing_instance_name}</td>
                  <td style={{ fontWeight: 600 }}>
                    {p.remote_address}
                    {p.remote_hostname && <div className="text-muted" style={{ fontSize: '0.85em', fontWeight: 400 }}>{p.remote_hostname}</div>}
                  </td>
                  <td>{formatAsn(p.remote_asn)}</td>
                  <td>{p.peer_group_name || <Dash />}</td>
                  <td>{p.address_families.join(', ') || <Dash />}</td>
                  <td>
                    <RoutingStatusBadge status={p.status} />
                  </td>
                  {canWrite && (
                    <td style={RIGHT} onClick={(e) => e.stopPropagation()}>
                      <RowActions
                        label={`peering with ${p.remote_address}`}
                        onEdit={() => setEditingPeering(p)}
                        onDelete={() =>
                          void remove(`p${p.id}`, 'Delete peering', `Delete the peering of ${p.hostname} with ${p.remote_address}? This cannot be undone.`, 'Delete peering', () =>
                            removePeering.mutateAsync(p.id),
                          )
                        }
                        deleting={deleting.isPending(`p${p.id}`)}
                      />
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </DataTable>
      </CatalogueBody>

      <div style={{ marginTop: 'var(--space-5)' }}>
        <CardHeader title="Peer groups" sub={groupsQ.data && `${groups.length.toLocaleString()} peer group${groups.length === 1 ? '' : 's'}`} />
        <CatalogueBody
          query={groupsQ}
          what="peer groups"
          rows={groups}
          empty={<EmptyState compact message="No peer groups." description="A peer group holds the remote AS and policies its peerings share." />}
        >
          <DataTable compact aria-label="Peer groups">
            <thead>
              <tr>
                <th>Device</th>
                <th>Instance</th>
                <th>Name</th>
                <th>Remote AS</th>
                <th>Policies</th>
                <th style={RIGHT}>Peerings</th>
                {canWrite && <th style={RIGHT}>Actions</th>}
              </tr>
            </thead>
            <tbody>
              {groups.map((g) => {
                const isSelected = selected?.kind === 'group' && selected.id === g.id;
                return (
                  <tr
                    key={g.id}
                    className={`row-clickable${isSelected ? ' row-selected' : ''}`}
                    aria-current={isSelected ? 'true' : undefined}
                    title="Show the peer group's change history"
                    {...clickableProps(() => setSelected({ kind: 'group', id: g.id }), { role: null })}
                  >
                    <td>{g.hostname}</td>
                    <td>{g.routing_instance_name}</td>
                    <td style={{ fontWeight: 600 }}>{g.name}</td>
                    <td>{formatAsn(g.remote_asn)}</td>
                    <td>{[g.import_policy && `in ${g.import_policy}`, g.export_policy && `out ${g.export_policy}`].filter(Boolean).join(', ') || <Dash />}</td>
                    <td style={RIGHT}>{g.peering_count}</td>
                    {canWrite && (
                      <td style={RIGHT} onClick={(e) => e.stopPropagation()}>
                        <RowActions
                          label={`peer group ${g.name}`}
                          onEdit={() => setEditingGroup(g)}
                          onDelete={() =>
                            void remove(`g${g.id}`, 'Delete peer group', `Delete peer group "${g.name}"? Its peerings stay, without a group.`, 'Delete peer group', () =>
                              removeGroup.mutateAsync(g.id),
                            )
                          }
                          deleting={deleting.isPending(`g${g.id}`)}
                        />
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </DataTable>
        </CatalogueBody>
      </div>
      {editingPeering && <PeeringModal record={editingPeering === 'new' ? null : editingPeering} onClose={() => setEditingPeering(null)} />}
      {editingGroup && <PeerGroupModal record={editingGroup === 'new' ? null : editingGroup} onClose={() => setEditingGroup(null)} />}
    </>
  );

  const groupRecord = selected?.kind === 'group' ? groups.find((g) => g.id === selected.id) : undefined;
  const detail =
    selected?.kind === 'peering' ? (
      <PeeringDetailPanel id={selected.id} />
    ) : groupRecord ? (
      <div style={DETAIL_STACK_STYLE}>
        <div>
          <h3 style={{ margin: 0 }}>Peer group {groupRecord.name}</h3>
          <div className="text-muted" style={{ fontSize: '0.9em' }}>
            {[groupRecord.hostname, groupRecord.routing_instance_name, groupRecord.remote_asn !== null && formatAsn(groupRecord.remote_asn), groupRecord.description]
              .filter(Boolean)
              .join(' · ')}
          </div>
        </div>
        <ChangelogPanel objectType="bgp_peer_group" objectId={groupRecord.id} pageSize={10} />
      </div>
    ) : (
      <>
        <h3 style={{ margin: '0 0 0.75rem' }}>Peering details</h3>
        <p className="text-muted" style={{ margin: 0 }}>
          Select a peering or a peer group to see its details and change history.
        </p>
      </>
    );

  return <SplitLayout list={list} detail={detail} />;
}

function PeeringDetailPanel({ id }: { id: number }) {
  const q = useBgpPeering(id);
  if (q.isError && !q.data) return <QueryError what="peering details" query={q} />;
  if (q.isPending) return <LoadingState text="Loading peering details…" />;
  const p = q.data;
  const facts: [string, string][] = [
    ['Device', `${p.hostname} · ${p.routing_instance_name} (${formatAsn(p.local_asn)})`],
    ['Local address', p.local_address || '-'],
    ['Remote address', p.remote_address],
    ['Remote AS', formatAsn(p.remote_asn)],
    ['Peer device', p.remote_hostname || '-'],
    ['Peer group', p.peer_group_name || '-'],
    ['Address families', p.address_families.join(', ') || '-'],
    ['Import policy', p.import_policy || '-'],
    ['Export policy', p.export_policy || '-'],
  ];
  return (
    <div style={DETAIL_STACK_STYLE}>
      <div>
        <h3 style={{ margin: 0 }}>Peering with {p.remote_address}</h3>
        <div style={{ marginTop: '0.25rem' }}>
          <RoutingStatusBadge status={p.status} /> {p.description && <span className="text-muted">{p.description}</span>}
        </div>
      </div>
      <dl style={{ display: 'grid', gridTemplateColumns: 'max-content 1fr', gap: '0.3rem 0.75rem', margin: 0 }}>
        {facts.map(([k, v]) => (
          <div key={k} style={{ display: 'contents' }}>
            <dt className="text-muted">{k}</dt>
            <dd style={{ margin: 0, wordBreak: 'break-word' }}>{v}</dd>
          </div>
        ))}
      </dl>
      <ChangelogPanel objectType="bgp_peering" objectId={p.id} pageSize={10} />
    </div>
  );
}
