import { useState } from 'react';

import { useAuthStatus } from '@/api/auth';
import { type OrgSite, useDeleteSite, useOrgSites } from '@/api/organization';
import { Badge } from '@/components/Badge';
import { CardHeader, CatalogueBody, Dash, RowActions } from '@/components/CatalogueParts';
import { ChangelogPanel } from '@/components/ChangelogPanel';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { useConfirmDelete } from '@/components/useConfirmDelete';
import { clickableProps } from '@/lib/clickable';
import { siteStatusLabel, siteStatusTone } from '@/lib/organization';
import { canUseFeature } from '@/lib/tabGating';
import { usePendingKeys } from '@/lib/usePendingKeys';
import { SiteModal } from '@/pages/FloorPlan/modals';
import { SplitLayout } from '@/pages/Ipam/NetworkObjectParts';

const RIGHT = { textAlign: 'right' } as const;

/**
 * The Sites tab: every site with its region, status, facility, time zone and
 * tenant. Sites are written through the Floor Plans API, so changing one
 * needs the floor plan feature (admins have it).
 */
export function SitesTab() {
  const auth = useAuthStatus().data;
  const canWrite = auth?.role === 'admin' || canUseFeature('floor-plan', auth);
  const q = useOrgSites();
  const remove = useDeleteSite();
  const confirmDelete = useConfirmDelete();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<OrgSite | 'new' | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const rows = q.data ?? [];
  const selected = rows.find((s) => s.id === selectedId) ?? null;

  const addButton = canWrite && (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      Add site
    </button>
  );

  const list = (
    <>
      <CardHeader
        title="Sites"
        sub={q.data && `${rows.length.toLocaleString()} site${rows.length === 1 ? '' : 's'}`}
        actions={rows.length > 0 && addButton}
      />
      <CatalogueBody
        query={q}
        what="sites"
        rows={rows}
        empty={
          <EmptyState
            compact
            message="No sites yet."
            description="A site is a building or campus. Give it a region, a status and a time zone, and place hosts in it."
            action={addButton || undefined}
          />
        }
      >
        <DataTable compact aria-label="Sites">
          <thead>
            <tr>
              <th>Name</th>
              <th>Region</th>
              <th>Status</th>
              <th>Facility</th>
              <th>Time zone</th>
              <th>Tenant</th>
              <th style={RIGHT}>Hosts</th>
              {canWrite && <th style={RIGHT}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((s) => {
              const isSelected = s.id === selectedId;
              return (
                <tr
                  key={s.id}
                  className={`row-clickable${isSelected ? ' row-selected' : ''}`}
                  aria-current={isSelected ? 'true' : undefined}
                  title="Show the site's changes"
                  {...clickableProps(() => setSelectedId(s.id), { role: null })}
                >
                  <td style={{ fontWeight: 600 }}>{s.name}</td>
                  <td>{s.region_name || <Dash />}</td>
                  <td>
                    <Badge size="sm" tone={siteStatusTone(s.status)}>
                      {siteStatusLabel(s.status)}
                    </Badge>
                  </td>
                  <td>{s.facility || <Dash />}</td>
                  <td>{s.time_zone || <Dash />}</td>
                  <td>{s.tenant_name || <Dash />}</td>
                  <td style={RIGHT}>{(s.host_count ?? 0).toLocaleString()}</td>
                  {canWrite && (
                    <td style={RIGHT} onClick={(e) => e.stopPropagation()}>
                      <RowActions
                        label={`site ${s.name}`}
                        onEdit={() => setEditing(s)}
                        onDelete={() =>
                          void deleting.run(s.id, async () => {
                            if (await confirmDelete('site', s.name, () => remove.mutateAsync(s.id))) {
                              if (selectedId === s.id) setSelectedId(null);
                            }
                          })
                        }
                        deleting={deleting.isPending(s.id)}
                      />
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {editing && <SiteModal site={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </>
  );

  const detail = selected ? (
    <div style={{ display: 'grid', gap: '0.75rem' }}>
      <div>
        <h3 style={{ margin: 0 }}>{selected.name}</h3>
        <div className="text-muted" style={{ fontSize: '0.9em' }}>
          {[selected.region_name, selected.facility, selected.address].filter(Boolean).join(' · ') || 'No region'}
        </div>
      </div>
      <ChangelogPanel objectType="site" objectId={selected.id} />
    </div>
  ) : (
    <EmptyState compact message="Select a site to see its changes." />
  );

  return <SplitLayout list={list} detail={detail} />;
}
