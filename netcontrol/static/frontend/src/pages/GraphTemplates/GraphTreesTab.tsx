import { useState } from 'react';

import { Callout } from '@/components/Callout';
import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  useDeleteGraphTree,
  useGraphTrees,
  type GraphTree,
} from '@/api/graphTemplates';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';

import { GraphTreeFormModal } from './GraphTreeFormModal';
import { GraphTreeDetailModal } from './GraphTreeDetailModal';

export function GraphTreesTab() {
  const { confirm, alert } = useDialogs();
  const query = useGraphTrees();
  const deleteMut = useDeleteGraphTree();
  const [formMode, setFormMode] = useState<{ mode: 'create' } | { mode: 'edit'; treeId: number } | null>(null);
  const [detailId, setDetailId] = useState<number | null>(null);

  const items: GraphTree[] = query.data?.graph_trees ?? [];

  async function handleDelete(tree: GraphTree) {
    if (
      !(await confirm({
        title: 'Delete graph tree',
        message: `Delete graph tree "${tree.name}" and all its nodes?`,
        confirmLabel: 'Delete',
      }))
    )
      return;
    deleteMut.mutate(tree.id, {
      onError: (e) => { void alert({ message: (e as Error).message, variant: 'error' }); },
    });
  }

  return (
    <div>
      <div className="toolbar" style={{ justifyContent: 'flex-end' }}>
        <button className="btn btn-primary" onClick={() => setFormMode({ mode: 'create' })}>+ New Tree</button>
      </div>

      {query.isPending && <LoadingState />}
      {query.error && <Callout tone="danger">Failed: {(query.error as Error).message}</Callout>}
      {query.data && (items.length === 0 ? (
        <EmptyState message="No graph trees configured. Create a tree to organize graphs hierarchically." />
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '1rem' }}>
          {items.map((tree) => (
            <div key={tree.id} className="card">
              <button
                type="button"
                onClick={() => setDetailId(tree.id)}
                style={{ background: 'none', border: 'none', textAlign: 'left', padding: 0, cursor: 'pointer', color: 'inherit', width: '100%' }}
              >
                <h4 style={{ margin: '0 0 0.5rem' }}>{tree.name}</h4>
                <p className="text-muted" style={{ margin: 0, fontSize: '0.85rem' }}>
                  {tree.description || 'No description'}
                </p>
              </button>
              <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.75rem' }}>
                <button className="btn btn-sm btn-secondary" onClick={() => setFormMode({ mode: 'edit', treeId: tree.id })}>Edit</button>
                <DeleteButton onClick={() => handleDelete(tree)} />
              </div>
            </div>
          ))}
        </div>
      ))}

      <GraphTreeFormModal
        mode={formMode?.mode ?? null}
        treeId={formMode?.mode === 'edit' ? formMode.treeId : null}
        onClose={() => setFormMode(null)}
      />
      <GraphTreeDetailModal treeId={detailId} onClose={() => setDetailId(null)} />
    </div>
  );
}
