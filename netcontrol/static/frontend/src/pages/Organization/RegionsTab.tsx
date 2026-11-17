import { Fragment, type ReactNode, useState } from 'react';

import {
  type LocationRegion,
  type LocationSite,
  type Region,
  useDeleteRegion,
  useLocationTree,
  useRegions,
} from '@/api/organization';
import { Badge } from '@/components/Badge';
import { CardHeader, CatalogueBody, Dash, RowActions } from '@/components/CatalogueParts';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { useConfirmDelete } from '@/components/useConfirmDelete';
import { siteStatusLabel, siteStatusTone } from '@/lib/organization';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { TreeNodeModal } from './OrganizationModals';
import { useIsOrgAdmin } from './useIsOrgAdmin';

const RIGHT = { textAlign: 'right' } as const;
const indent = (depth: number) => ({ paddingLeft: `${0.5 + depth * 1.25}rem` });

/** The Regions tab: the region tree with the sites (and their floors) under each region. */
export function RegionsTab() {
  const isAdmin = useIsOrgAdmin();
  const treeQ = useLocationTree();
  const regionsQ = useRegions();
  const remove = useDeleteRegion();
  const confirmDelete = useConfirmDelete();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<{ node: Region | null; parentId: number | null } | null>(null);
  const tree = treeQ.data;
  const regionCount = regionsQ.data?.length ?? 0;
  const rows: (LocationRegion | LocationSite)[] = tree ? [...tree.regions, ...tree.unassigned_sites] : [];
  const listQ = { ...treeQ, data: tree ? rows : undefined };
  const byId = new Map((regionsQ.data ?? []).map((r) => [r.id, r]));

  const addButton = isAdmin && (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing({ node: null, parentId: null })}>
      Add region
    </button>
  );

  const siteRow = (site: LocationSite, depth: number) => (
    <tr key={`site-${site.id}`}>
      <td style={indent(depth)}>
        <span className="text-muted" aria-hidden="true">
          {'└ '}
        </span>
        {site.name}{' '}
        <Badge size="sm" tone={siteStatusTone(site.status)}>
          {siteStatusLabel(site.status)}
        </Badge>
      </td>
      <td>Site{site.facility ? ` · ${site.facility}` : ''}</td>
      <td style={RIGHT}>{site.floors.length.toLocaleString()} floors</td>
      <td style={RIGHT}>{site.host_count.toLocaleString()}</td>
      <td>{site.tenant_name || <Dash />}</td>
      {isAdmin && <td />}
    </tr>
  );

  const regionRows = (region: LocationRegion, depth: number): ReactNode => {
    const record = byId.get(region.id) ?? region;
    return (
      <Fragment key={`region-${region.id}`}>
        <tr>
          <td style={{ ...indent(depth), fontWeight: 600 }}>{region.name}</td>
          <td>{region.description || <Dash />}</td>
          <td style={RIGHT}>{region.total_site_count.toLocaleString()} sites</td>
          <td style={RIGHT}>{region.host_count.toLocaleString()}</td>
          <td />
          {isAdmin && (
            <td style={RIGHT}>
              <div className="table-actions" style={{ justifyContent: 'flex-end' }}>
                <button
                  type="button"
                  className="btn btn-sm btn-secondary"
                  aria-label={`Add a region under ${region.name}`}
                  onClick={() => setEditing({ node: null, parentId: region.id })}
                >
                  Add child
                </button>
                <RowActions
                  label={`region ${region.name}`}
                  onEdit={() => setEditing({ node: record, parentId: record.parent_id })}
                  onDelete={() =>
                    void deleting.run(region.id, () =>
                      confirmDelete('region', region.name, () => remove.mutateAsync(region.id)),
                    )
                  }
                  deleting={deleting.isPending(region.id)}
                />
              </div>
            </td>
          )}
        </tr>
        {region.children.map((child) => regionRows(child, depth + 1))}
        {region.sites.map((site) => siteRow(site, depth + 1))}
      </Fragment>
    );
  };

  return (
    <div className="card">
      <CardHeader
        title="Regions"
        sub={tree && `${regionCount.toLocaleString()} region${regionCount === 1 ? '' : 's'}`}
        actions={regionCount > 0 && addButton}
      />
      <CatalogueBody
        query={listQ}
        what="regions"
        rows={rows}
        empty={
          <EmptyState
            compact
            message="No regions or sites yet."
            description="Regions group sites by geography (Europe > Netherlands > Amsterdam). Add a region, then give sites a region on the Sites tab."
            action={addButton || undefined}
          />
        }
      >
        <DataTable compact aria-label="Regions and sites">
          <thead>
            <tr>
              <th>Name</th>
              <th>Details</th>
              <th style={RIGHT}>Contains</th>
              <th style={RIGHT}>Hosts</th>
              <th>Tenant</th>
              {isAdmin && <th style={RIGHT}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {tree?.regions.map((region) => regionRows(region, 0))}
            {tree && tree.unassigned_sites.length > 0 && (
              <>
                <tr>
                  <td colSpan={isAdmin ? 6 : 5} className="text-muted" style={{ fontWeight: 600 }}>
                    Sites in no region
                  </td>
                </tr>
                {tree.unassigned_sites.map((site) => siteRow(site, 1))}
              </>
            )}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {editing && (
        <TreeNodeModal
          kind="region"
          node={editing.node}
          defaultParentId={editing.parentId}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  );
}
