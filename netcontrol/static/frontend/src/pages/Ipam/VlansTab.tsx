import { useId, useState } from 'react';

import { useAuthStatus } from '@/api/auth';
import { useGeoSites } from '@/api/floorPlan';
import { type Vlan, useDeleteVlan, useVlan, useVlans } from '@/api/networkObjects';
import { Badge } from '@/components/Badge';
import { CatalogueBody, RowActions } from '@/components/CatalogueParts';
import { DataTable } from '@/components/DataTable';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { clickableProps } from '@/lib/clickable';
import { siteFilterFromSelect, siteFilterToSelect, type VlanSiteFilter, vrfLabel } from '@/lib/networkObjects';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { VlanModal } from './NetworkObjectModals';
import { CardHeader, Dash, DetailSection, OriginBadge, SplitLayout } from './NetworkObjectParts';

const RIGHT = { textAlign: 'right' } as const;

/** The IPAM page's VLANs tab: the VLAN records by site, and the selected one's devices, ports and prefixes. */
export function VlansTab() {
  const filterId = useId();
  const isAdmin = useAuthStatus().data?.role === 'admin';
  const sitesQ = useGeoSites();
  const [site, setSite] = useState<VlanSiteFilter>('all');
  const q = useVlans(site);
  const remove = useDeleteVlan();
  const { confirm, alert } = useDialogs();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<Vlan | 'new' | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const rows = q.data ?? [];

  const addButton = isAdmin && (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      Add VLAN
    </button>
  );

  const handleDelete = (v: Vlan) =>
    void deleting.run(v.id, async () => {
      const carried =
        v.device_count > 0
          ? ` ${v.device_count === 1 ? 'A device still carries' : `${v.device_count.toLocaleString()} devices still carry`} it, so it is created again at their next collection.`
          : '';
      const agreed = await confirm({
        title: 'Delete VLAN',
        message: `Delete VLAN ${v.vid}${v.name ? ` (${v.name})` : ''}?${carried} This cannot be undone.`,
        confirmLabel: 'Delete VLAN',
      });
      if (!agreed) return;
      try {
        await remove.mutateAsync(v.id);
        if (selectedId === v.id) setSelectedId(null);
      } catch (err) {
        await alert({ message: `VLAN ${v.vid} was not deleted: ${(err as Error).message} Try again.`, variant: 'error' });
      }
    });

  const filtered = site !== 'all';
  const siteFilter = (
    <label style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }} htmlFor={`${filterId}-site`}>
      Site
      <select
        id={`${filterId}-site`}
        className="form-select"
        value={siteFilterToSelect(site)}
        onChange={(e) => setSite(siteFilterFromSelect(e.target.value))}
      >
        <option value="all">All sites</option>
        <option value="none">No site (global)</option>
        {(sitesQ.data ?? []).map((s) => (
          <option key={s.id} value={s.id}>
            {s.name}
          </option>
        ))}
      </select>
    </label>
  );

  const list = (
    <>
      <CardHeader
        title="VLANs"
        sub={q.data && `${rows.length.toLocaleString()} VLAN${rows.length === 1 ? '' : 's'}${filtered ? ' for this filter' : ''}`}
        actions={
          <>
            {siteFilter}
            {rows.length > 0 && addButton}
          </>
        }
      />
      <CatalogueBody
        query={q}
        what="VLANs"
        rows={rows}
        empty={
          filtered ? (
            <EmptyState
              compact
              message="No VLANs for this site."
              action={
                <button type="button" className="btn btn-sm btn-secondary" onClick={() => setSite('all')}>
                  Show all sites
                </button>
              }
            />
          ) : (
            <EmptyState
              compact
              message="No VLANs yet."
              description="Plexus adds the VLANs devices report when it collects their inventory. An admin can add one by hand."
              action={addButton || undefined}
            />
          )
        }
      >
        <DataTable compact aria-label="VLANs">
          <thead>
            <tr>
              <th style={RIGHT}>VLAN ID</th>
              <th>Name</th>
              <th>Site</th>
              <th>Origin</th>
              <th style={RIGHT}>Devices</th>
              <th style={RIGHT}>Ports</th>
              <th style={RIGHT}>Prefixes</th>
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
                  title="Show the VLAN's details"
                  {...clickableProps(() => setSelectedId(v.id), { role: null })}
                >
                  <td style={{ ...RIGHT, fontWeight: 600 }}>{v.vid}</td>
                  <td>
                    <span className="tag-chips">
                      {v.name || <Dash />}
                      {v.name_mismatch && (
                        <Badge size="sm" tone="warning" title="A device names this VLAN differently">
                          Name differs
                        </Badge>
                      )}
                    </span>
                  </td>
                  <td>{v.site ? v.site.name : <span className="text-muted">Global</span>}</td>
                  <td>
                    <OriginBadge origin={v.origin} />
                  </td>
                  <td style={RIGHT}>{v.device_count.toLocaleString()}</td>
                  <td style={RIGHT}>{v.interface_count.toLocaleString()}</td>
                  <td style={RIGHT}>{v.prefix_count.toLocaleString()}</td>
                  <td>{v.description || <Dash />}</td>
                  {isAdmin && (
                    // The row opens the detail panel; the buttons do their own thing.
                    <td style={RIGHT} onClick={(e) => e.stopPropagation()}>
                      <RowActions
                        label={`VLAN ${v.vid}`}
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
      {editing && <VlanModal vlan={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </>
  );

  return <SplitLayout list={list} detail={<VlanDetailPanel id={selectedId} />} />;
}

export function VlanDetailPanel({ id }: { id: number | null }) {
  const q = useVlan(id);
  if (id === null) {
    return (
      <>
        <h3 style={{ margin: '0 0 0.75rem' }}>VLAN details</h3>
        <p className="text-muted" style={{ margin: 0 }}>
          Select a VLAN to see the devices that carry it, their ports in it and its prefixes.
        </p>
      </>
    );
  }
  if (q.isError && !q.data) {
    return (
      <>
        <h3 style={{ margin: '0 0 0.75rem' }}>VLAN details</h3>
        <QueryError what="VLAN details" query={q} />
      </>
    );
  }
  if (q.isPending) return <LoadingState text="Loading VLAN details…" />;
  const v = q.data;
  return (
    <div style={{ display: 'grid', gap: '1rem' }}>
      <div>
        <h3 style={{ margin: 0 }}>
          VLAN {v.vid}
          {v.name ? ` ${v.name}` : ''}
        </h3>
        <div className="text-muted" style={{ fontSize: '0.9em' }}>
          {v.site ? `Site ${v.site.name}` : 'No site (global)'}
          {v.description ? ` · ${v.description}` : ''}
        </div>
      </div>
      <DetailSection title="Devices" count={v.devices.length} empty="No device carries this VLAN.">
        <DataTable compact aria-label={`Devices with VLAN ${v.vid}`} maxHeight={240}>
          <thead>
            <tr>
              <th>Device</th>
              <th>Its name for the VLAN</th>
              <th>State</th>
            </tr>
          </thead>
          <tbody>
            {v.devices.map((d) => (
              <tr key={d.host_id}>
                <td>{d.hostname}</td>
                <td>
                  <span className="tag-chips">
                    {d.name || <Dash />}
                    {!d.name_matches && (
                      <Badge size="sm" tone="warning" title="Differs from the record's name">
                        Differs
                      </Badge>
                    )}
                  </span>
                </td>
                <td>{d.state || <Dash />}</td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      </DetailSection>
      <DetailSection
        title="Ports"
        count={v.interfaces.length}
        empty="No port is in this VLAN."
        note={v.truncated ? `Showing the first ${v.interfaces.length.toLocaleString()} ports; more exist.` : undefined}
      >
        <DataTable compact aria-label={`Ports in VLAN ${v.vid}`} maxHeight={320}>
          <thead>
            <tr>
              <th>Device</th>
              <th>Interface</th>
              <th>Mode</th>
            </tr>
          </thead>
          <tbody>
            {v.interfaces.map((p) => (
              <tr key={`${p.host_id}|${p.interface}`}>
                <td>{p.hostname}</td>
                <td>{p.interface}</td>
                <td>{p.mode === 'trunk' ? 'Trunk' : p.mode === 'access' ? 'Access' : p.mode}</td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      </DetailSection>
      <DetailSection title="Prefixes" count={v.prefixes.length} empty="No VLAN interface carries an address in this VLAN.">
        <DataTable compact aria-label={`Prefixes of VLAN ${v.vid}`} maxHeight={240}>
          <thead>
            <tr>
              <th>Network</th>
              <th>VRF</th>
              <th>Device</th>
              <th>Interface</th>
              <th>Address</th>
            </tr>
          </thead>
          <tbody>
            {v.prefixes.map((p) => (
              <tr key={`${p.network}|${p.host_id}|${p.interface}|${p.address}`}>
                <td>{p.network}</td>
                <td>{p.vrf_name ? p.vrf_name : <span className="text-muted">{vrfLabel(p.vrf_name)}</span>}</td>
                <td>{p.hostname}</td>
                <td>{p.interface}</td>
                <td>{p.address}</td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      </DetailSection>
    </div>
  );
}
