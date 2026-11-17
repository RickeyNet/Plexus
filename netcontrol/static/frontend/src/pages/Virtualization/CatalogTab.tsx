import { useState } from 'react';

import {
  type ClusterCatalogItem,
  useClusterGroups,
  useClusterTypes,
  useDeleteClusterGroup,
  useDeleteClusterType,
} from '@/api/virtualization';
import { CardHeader, CatalogueBody, Dash, RowActions } from '@/components/CatalogueParts';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { CatalogModal } from './VirtualizationModals';
import { useCanWriteVirtualization, useConfirmDelete } from './virtualizationHooks';

const RIGHT = { textAlign: 'right' } as const;

/** The Cluster types (`kind` type) or Cluster groups tab. */
export function CatalogTab({ kind }: { kind: 'type' | 'group' }) {
  const canWrite = useCanWriteVirtualization();
  const types = useClusterTypes();
  const groups = useClusterGroups();
  const removeType = useDeleteClusterType();
  const removeGroup = useDeleteClusterGroup();
  const q = kind === 'type' ? types : groups;
  const remove = kind === 'type' ? removeType : removeGroup;
  const what = kind === 'type' ? 'cluster type' : 'cluster group';
  const title = kind === 'type' ? 'Cluster types' : 'Cluster groups';
  const confirmDelete = useConfirmDelete();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<ClusterCatalogItem | 'new' | null>(null);
  const rows = q.data ?? [];

  const addButton = canWrite && (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      Add {what}
    </button>
  );

  return (
    <div className="card">
      <CardHeader
        title={title}
        sub={q.data && `${rows.length.toLocaleString()} ${rows.length === 1 ? what : `${what}s`}`}
        actions={rows.length > 0 && addButton}
      />
      <CatalogueBody
        query={q}
        what={`${what}s`}
        rows={rows}
        empty={
          <EmptyState
            compact
            message={`No ${what}s yet.`}
            description={
              kind === 'type'
                ? 'A cluster type says what runs a cluster: VMware vSphere, Proxmox, Hyper-V. The cloud sync adds AWS EC2, Azure and GCP.'
                : 'Cluster groups file clusters together, by environment or team.'
            }
            action={addButton || undefined}
          />
        }
      >
        <DataTable compact aria-label={title}>
          <thead>
            <tr>
              <th>Name</th>
              <th style={RIGHT}>Clusters</th>
              <th>Description</th>
              {canWrite && <th style={RIGHT}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id}>
                <td style={{ fontWeight: 600 }}>{row.name}</td>
                <td style={RIGHT}>{row.cluster_count.toLocaleString()}</td>
                <td>{row.description || <Dash />}</td>
                {canWrite && (
                  <td style={RIGHT}>
                    <RowActions
                      label={`${what} ${row.name}`}
                      onEdit={() => setEditing(row)}
                      onDelete={() =>
                        void deleting.run(row.id, () => confirmDelete(what, row.name, () => remove.mutateAsync(row.id)))
                      }
                      deleting={deleting.isPending(row.id)}
                    />
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {editing && <CatalogModal kind={kind} item={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </div>
  );
}
