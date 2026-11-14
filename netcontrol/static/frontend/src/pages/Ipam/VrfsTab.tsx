import { useState } from 'react';

import { useAuthStatus } from '@/api/auth';
import { CustomDataError } from '@/api/customData';
import { type Vrf, useDeleteVrf, useRebuildInterfaceAddresses, useVrf, useVrfs } from '@/api/networkObjects';
import { BusyButton } from '@/components/BusyButton';
import { CatalogueBody, RowActions } from '@/components/CatalogueParts';
import { DataTable } from '@/components/DataTable';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { clickableProps } from '@/lib/clickable';
import { addressRoleLabel, formatInterfaceAddress } from '@/lib/networkObjects';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { VrfModal } from './NetworkObjectModals';
import { CardHeader, Dash, DetailSection, OriginBadge, SplitLayout } from './NetworkObjectParts';

const RIGHT = { textAlign: 'right' } as const;

/** The IPAM page's VRFs tab: the VRF records, and the selected one's devices, addresses and prefixes. */
export function VrfsTab() {
  const isAdmin = useAuthStatus().data?.role === 'admin';
  const q = useVrfs();
  const remove = useDeleteVrf();
  const rebuild = useRebuildInterfaceAddresses();
  const { confirm, alert } = useDialogs();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<Vrf | 'new' | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const rows = q.data ?? [];

  const addButton = isAdmin && (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      Add VRF
    </button>
  );

  const handleDelete = (v: Vrf) =>
    void deleting.run(v.id, async () => {
      const agreed = await confirm({
        title: 'Delete VRF',
        message: `Delete VRF "${v.name}"? This cannot be undone.`,
        confirmLabel: 'Delete VRF',
      });
      if (!agreed) return;
      try {
        await remove.mutateAsync(v.id);
        if (selectedId === v.id) setSelectedId(null);
      } catch (err) {
        // A VRF in use is a 409 whose message names what still uses it.
        const inUse = err instanceof CustomDataError && err.status === 409;
        await alert({
          title: inUse ? 'VRF in use' : 'VRF not deleted',
          message: inUse ? (err as Error).message : `The VRF "${v.name}" was not deleted: ${(err as Error).message} Try again.`,
          variant: 'error',
        });
      }
    });

  const handleRebuild = async () => {
    try {
      const res = await rebuild.mutateAsync();
      await alert({
        title: 'Interface addresses rebuilt',
        message: `Read ${res.addresses.toLocaleString()} addresses from the stored configurations of ${res.hosts.toLocaleString()} devices.`,
      });
    } catch (err) {
      await alert({ message: `The interface addresses were not rebuilt: ${(err as Error).message} Try again.`, variant: 'error' });
    }
  };

  const list = (
    <>
      <CardHeader
        title="VRFs"
        sub={q.data && `${rows.length.toLocaleString()} VRF${rows.length === 1 ? '' : 's'}`}
        actions={
          isAdmin && (
            <>
              <BusyButton className="btn btn-sm btn-secondary" busy={rebuild.isPending} busyLabel="Rebuilding…" onClick={() => void handleRebuild()}>
                Rebuild interface addresses
              </BusyButton>
              {rows.length > 0 && addButton}
            </>
          )
        }
      />
      <CatalogueBody
        query={q}
        what="VRFs"
        rows={rows}
        empty={
          <EmptyState
            compact
            message="No VRFs yet."
            description="Plexus adds the VRFs it finds on hosts, IPAM prefixes and device configurations. An admin can add one by hand."
            action={addButton || undefined}
          />
        }
      >
        <DataTable compact aria-label="VRFs">
          <thead>
            <tr>
              <th>Name</th>
              <th>RD</th>
              <th>Origin</th>
              <th style={RIGHT}>Devices</th>
              <th style={RIGHT}>Hosts</th>
              <th style={RIGHT}>Prefixes</th>
              <th style={RIGHT}>Addresses</th>
              <th>Description</th>
              {isAdmin && <th style={RIGHT}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((v) => {
              const selected = v.id === selectedId;
              return (
                <tr
                  key={v.id}
                  className={`row-clickable${selected ? ' row-selected' : ''}`}
                  aria-current={selected ? 'true' : undefined}
                  title="Show the VRF's details"
                  {...clickableProps(() => setSelectedId(v.id), { role: null })}
                >
                  <td style={{ fontWeight: 600 }}>{v.name}</td>
                  <td>{v.rd || <Dash />}</td>
                  <td>
                    <OriginBadge origin={v.origin} />
                  </td>
                  <td style={RIGHT}>{v.device_count.toLocaleString()}</td>
                  <td style={RIGHT}>{v.host_count.toLocaleString()}</td>
                  <td style={RIGHT}>{v.prefix_count.toLocaleString()}</td>
                  <td style={RIGHT}>{v.address_count.toLocaleString()}</td>
                  <td>{v.description || <Dash />}</td>
                  {isAdmin && (
                    // The row opens the detail panel; the buttons do their own thing.
                    <td style={RIGHT} onClick={(e) => e.stopPropagation()}>
                      <RowActions
                        label={`VRF ${v.name}`}
                        onEdit={() => setEditing(v)}
                        onDelete={() => handleDelete(v)}
                        deleting={deleting.isPending(v.id)}
                      />
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {editing && <VrfModal vrf={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </>
  );

  return <SplitLayout list={list} detail={<VrfDetailPanel id={selectedId} />} />;
}

export function VrfDetailPanel({ id }: { id: number | null }) {
  const q = useVrf(id);
  if (id === null) {
    return (
      <>
        <h3 style={{ margin: '0 0 0.75rem' }}>VRF details</h3>
        <p className="text-muted" style={{ margin: 0 }}>
          Select a VRF to see its devices, interface addresses and prefixes.
        </p>
      </>
    );
  }
  if (q.isError && !q.data) {
    return (
      <>
        <h3 style={{ margin: '0 0 0.75rem' }}>VRF details</h3>
        <QueryError what="VRF details" query={q} />
      </>
    );
  }
  if (q.isPending) return <LoadingState text="Loading VRF details…" />;
  const v = q.data;
  return (
    <div style={{ display: 'grid', gap: '1rem' }}>
      <div>
        <h3 style={{ margin: 0 }}>VRF {v.name}</h3>
        <div className="text-muted" style={{ fontSize: '0.9em' }}>
          {v.rd ? `RD ${v.rd}` : 'No route distinguisher'}
          {v.description ? ` · ${v.description}` : ''}
        </div>
      </div>
      <DetailSection title="Devices" count={v.devices.length} empty="No device has an interface or route in this VRF.">
        <DataTable compact aria-label={`Devices in VRF ${v.name}`} maxHeight={240}>
          <thead>
            <tr>
              <th>Device</th>
              <th style={RIGHT}>Interfaces</th>
            </tr>
          </thead>
          <tbody>
            {v.devices.map((d) => (
              <tr key={d.host_id}>
                <td>{d.hostname}</td>
                <td style={RIGHT}>{d.interface_count.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      </DetailSection>
      <DetailSection
        title="Interface addresses"
        count={v.interfaces.length}
        empty="No interface address in this VRF."
        note={v.truncated ? `Showing the first ${v.interfaces.length.toLocaleString()} addresses; more exist.` : undefined}
      >
        <DataTable compact aria-label={`Interface addresses in VRF ${v.name}`} maxHeight={320}>
          <thead>
            <tr>
              <th>Device</th>
              <th>Interface</th>
              <th>Address</th>
              <th>Role</th>
            </tr>
          </thead>
          <tbody>
            {v.interfaces.map((a) => (
              <tr key={`${a.host_id}|${a.interface}|${a.address}`}>
                <td>{a.hostname}</td>
                <td>{a.interface}</td>
                <td>{formatInterfaceAddress(a)}</td>
                <td>{addressRoleLabel(a)}</td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      </DetailSection>
      <DetailSection title="Prefixes" count={v.prefixes.length} empty="No prefix in this VRF.">
        <DataTable compact aria-label={`Prefixes in VRF ${v.name}`} maxHeight={240}>
          <thead>
            <tr>
              <th>Prefix</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            {v.prefixes.map((p) => (
              <tr key={`${p.subnet}|${p.source}`}>
                <td>{p.subnet}</td>
                <td>{p.source === 'interface' ? 'Interface' : p.source}</td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      </DetailSection>
    </div>
  );
}
