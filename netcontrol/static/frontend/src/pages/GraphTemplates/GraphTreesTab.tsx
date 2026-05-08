import { useState } from 'react';

import {
  useDeleteGraphTree,
  useGraphTrees,
  type GraphTree,
} from '@/api/graphTemplates';

import { GraphTreeFormModal } from './GraphTreeFormModal';
import { GraphTreeDetailModal } from './GraphTreeDetailModal';

export function GraphTreesTab() {
  const query = useGraphTrees();
  const deleteMut = useDeleteGraphTree();
  const [formMode, setFormMode] = useState<{ mode: 'create' } | { mode: 'edit'; treeId: number } | null>(null);
  const [detailId, setDetailId] = useState<number | null>(null);

  const items: GraphTree[] = query.data?.graph_trees ?? [];

  function handleDelete(id: number) {
    if (!confirm('Delete this graph tree and all its nodes?')) return;
    deleteMut.mutate(id, {
      onError: (e) => alert((e as Error).message),
    });
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '0.75rem' }}>
        <button className="btn btn-primary" onClick={() => setFormMode({ mode: 'create' })}>+ New Tree</button>
      </div>

      {query.isPending && <p className="text-muted">Loading…</p>}
      {query.error && <p style={{ color: 'var(--danger)' }}>Failed: {(query.error as Error).message}</p>}
      {query.data && (items.length === 0 ? (
        <div className="empty-state">
          No graph trees configured. Create a tree to organize graphs hierarchically.
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '1rem' }}>
          {items.map((tree) => (
            <div key={tree.id} className="card" style={{ padding: '1rem' }}>
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
                <button className="btn btn-sm btn-danger" onClick={() => handleDelete(tree.id)}>Delete</button>
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
