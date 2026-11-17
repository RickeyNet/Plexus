import { useState } from 'react';

import {
  type Tenant,
  type TenantGroup,
  useDeleteTenant,
  useDeleteTenantGroup,
  useTenant,
  useTenantGroups,
  useTenants,
} from '@/api/organization';
import { CardHeader, CatalogueBody, Dash, RowActions } from '@/components/CatalogueParts';
import { ChangelogPanel } from '@/components/ChangelogPanel';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { useConfirmDelete } from '@/components/useConfirmDelete';
import { clickableProps } from '@/lib/clickable';
import { tenantCountRows } from '@/lib/organization';
import { usePendingKeys } from '@/lib/usePendingKeys';
import { DETAIL_STACK_STYLE } from '@/lib/wideDetail';
import { SplitLayout } from '@/pages/Ipam/NetworkObjectParts';

import { TenantModal, TreeNodeModal } from './OrganizationModals';
import { useIsOrgAdmin } from './useIsOrgAdmin';

const RIGHT = { textAlign: 'right' } as const;

/** The Tenant groups tab: the group tree with each group's tenants. */
export function TenantGroupsTab() {
  const isAdmin = useIsOrgAdmin();
  const q = useTenantGroups();
  const remove = useDeleteTenantGroup();
  const confirmDelete = useConfirmDelete();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<TenantGroup | 'new' | null>(null);
  const rows = q.data ?? [];

  const addButton = isAdmin && (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      Add tenant group
    </button>
  );

  return (
    <div className="card">
      <CardHeader
        title="Tenant groups"
        sub={q.data && `${rows.length.toLocaleString()} group${rows.length === 1 ? '' : 's'}`}
        actions={rows.length > 0 && addButton}
      />
      <CatalogueBody
        query={q}
        what="tenant groups"
        rows={rows}
        empty={
          <EmptyState
            compact
            message="No tenant groups yet."
            description="Tenant groups file tenants, for example Customers > Retail. Groups nest."
            action={addButton || undefined}
          />
        }
      >
        <DataTable compact aria-label="Tenant groups">
          <thead>
            <tr>
              <th>Name</th>
              <th style={RIGHT}>Tenants</th>
              <th style={RIGHT}>With sub-groups</th>
              <th>Description</th>
              {isAdmin && <th style={RIGHT}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((g) => (
              <tr key={g.id}>
                <td style={{ paddingLeft: `${0.5 + g.depth * 1.25}rem`, fontWeight: 600 }}>{g.name}</td>
                <td style={RIGHT}>{g.tenant_count.toLocaleString()}</td>
                <td style={RIGHT}>{g.total_tenant_count.toLocaleString()}</td>
                <td>{g.description || <Dash />}</td>
                {isAdmin && (
                  <td style={RIGHT}>
                    <RowActions
                      label={`tenant group ${g.name}`}
                      onEdit={() => setEditing(g)}
                      onDelete={() =>
                        void deleting.run(g.id, () =>
                          confirmDelete('tenant group', g.name, () => remove.mutateAsync(g.id)),
                        )
                      }
                      deleting={deleting.isPending(g.id)}
                    />
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {editing && (
        <TreeNodeModal kind="tenant_group" node={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />
      )}
    </div>
  );
}

/** The Tenants tab: every tenant, and the selected one's owned objects and change log. */
export function TenantsTab() {
  const isAdmin = useIsOrgAdmin();
  const q = useTenants();
  const remove = useDeleteTenant();
  const confirmDelete = useConfirmDelete();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<Tenant | 'new' | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const rows = q.data ?? [];

  const addButton = isAdmin && (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      Add tenant
    </button>
  );

  const list = (
    <>
      <CardHeader
        title="Tenants"
        sub={q.data && `${rows.length.toLocaleString()} tenant${rows.length === 1 ? '' : 's'}`}
        actions={rows.length > 0 && addButton}
      />
      <CatalogueBody
        query={q}
        what="tenants"
        rows={rows}
        empty={
          <EmptyState
            compact
            message="No tenants yet."
            description="A tenant is who a host, site, prefix, IP address, VLAN or VRF belongs to: a customer, a business unit or a department."
            action={addButton || undefined}
          />
        }
      >
        <DataTable compact aria-label="Tenants">
          <thead>
            <tr>
              <th>Name</th>
              <th>Group</th>
              <th>Description</th>
              {isAdmin && <th style={RIGHT}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((t) => {
              const selected = t.id === selectedId;
              return (
                <tr
                  key={t.id}
                  className={`row-clickable${selected ? ' row-selected' : ''}`}
                  aria-current={selected ? 'true' : undefined}
                  title="Show what the tenant owns"
                  {...clickableProps(() => setSelectedId(t.id), { role: null })}
                >
                  <td style={{ fontWeight: 600 }}>{t.name}</td>
                  <td>{t.group_name || <Dash />}</td>
                  <td>{t.description || <Dash />}</td>
                  {isAdmin && (
                    <td style={RIGHT} onClick={(e) => e.stopPropagation()}>
                      <RowActions
                        label={`tenant ${t.name}`}
                        onEdit={() => setEditing(t)}
                        onDelete={() =>
                          void deleting.run(t.id, async () => {
                            const deleted = await confirmDelete('tenant', t.name, () => remove.mutateAsync(t.id));
                            if (deleted && selectedId === t.id) setSelectedId(null);
                          })
                        }
                        deleting={deleting.isPending(t.id)}
                      />
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {editing && <TenantModal tenant={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </>
  );

  return <SplitLayout list={list} detail={<TenantDetailPanel id={selectedId} />} />;
}

/** A tenant's description, what it owns per kind and its change log. */
export function TenantDetailPanel({ id }: { id: number | null }) {
  const q = useTenant(id);
  if (id === null) return <EmptyState compact message="Select a tenant to see what it owns." />;
  if (q.isError && !q.data) return <QueryError what="the tenant" query={q} />;
  if (!q.data) return <LoadingState text="Loading the tenant…" />;
  const t = q.data;
  const counts = tenantCountRows(t.counts);
  return (
    <div style={{ ...DETAIL_STACK_STYLE, gap: '0.75rem' }}>
      <div>
        <h3 style={{ margin: 0 }}>{t.name}</h3>
        <div className="text-muted" style={{ fontSize: '0.9em' }}>
          {[t.group_name, t.description].filter(Boolean).join(' · ') || 'No group'}
        </div>
      </div>
      {t.comments && <p style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{t.comments}</p>}
      <section aria-label="Owned objects">
        <div style={{ fontWeight: 600, marginBottom: '0.45rem' }}>Owns</div>
        <DataTable compact aria-label="Owned objects">
          <tbody>
            {counts.map((c) => (
              <tr key={c.key}>
                <td>{c.label}</td>
                <td style={RIGHT}>{c.count.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      </section>
      <ChangelogPanel objectType="tenant" objectId={t.id} />
    </div>
  );
}
