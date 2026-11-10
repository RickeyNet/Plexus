import { useId, useState, type FormEvent } from 'react';

import { Callout } from '@/components/Callout';
import { EmptyState } from '@/components/EmptyState';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import {
  useCreateGraphTreeNode,
  useGraphTree,
} from '@/api/graphTemplates';

interface Props {
  treeId: number | null;
  onClose: () => void;
}

export function GraphTreeDetailModal({ treeId, onClose }: Props) {
  const fid = useId();
  const isOpen = treeId != null;
  const query = useGraphTree(treeId);
  const createNodeMut = useCreateGraphTreeNode();

  const [addingNode, setAddingNode] = useState(false);
  const [title, setTitle] = useState('');
  const [nodeType, setNodeType] = useState('header');
  const [sortOrder, setSortOrder] = useState('0');
  const [titleError, setTitleError] = useState<string | null>(null);
  const [addError, setAddError] = useState<string | null>(null);

  function handleAddNode(e: FormEvent) {
    e.preventDefault();
    setAddError(null);
    if (!title.trim() || treeId == null) {
      setTitleError('Title is required');
      return;
    }
    createNodeMut.mutate(
      {
        treeId,
        data: {
          title: title.trim(),
          node_type: nodeType,
          sort_order: parseInt(sortOrder, 10) || 0,
        },
      },
      {
        onSuccess: () => {
          setAddingNode(false);
          setTitle(''); setNodeType('header'); setSortOrder('0');
        },
        onError: (err) => { setAddError((err as Error).message); },
      },
    );
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={query.data?.name ?? 'Graph Tree'}
      footer={<button type="button" className="btn btn-secondary" onClick={onClose}>Close</button>}
    >
      {query.isPending && <LoadingState />}
      {query.error && <Callout tone="danger">Failed: {(query.error as Error).message}</Callout>}
      {query.data && (() => {
        const tree = query.data;
        const nodes = tree.nodes ?? [];
        return (
          <>
            <p>{tree.description || ''}</p>
            <h4>Nodes ({nodes.length})</h4>
            {nodes.length ? (
              <table className="data-table">
                <thead><tr><th>Title</th><th>Type</th><th>Sort</th></tr></thead>
                <tbody>
                  {nodes.map((n) => (
                    <tr key={n.id}>
                      <td>{n.title || '-'}</td>
                      <td><span className="badge badge-secondary">{n.node_type}</span></td>
                      <td>{n.sort_order}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : <EmptyState compact message="No nodes yet. Add nodes to organize your graph hierarchy." />}

            {addingNode && addError && <Callout tone="danger">{addError}</Callout>}
            {addingNode ? (
              <form onSubmit={handleAddNode} style={{ marginTop: '0.75rem', display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'flex-end' }}>
                <div className="form-group" style={{ marginBottom: 0, flex: 1, minWidth: 200 }}>
                  <label className="form-label" htmlFor={`${fid}-title`}>Title</label>
                  <input
                    id={`${fid}-title`}
                    className="form-input"
                    value={title}
                    onChange={(e) => {
                      setTitle(e.target.value);
                      setTitleError(null);
                    }}
                    required
                    aria-invalid={!!titleError}
                  />
                  <FieldError>{titleError}</FieldError>
                </div>
                <div className="form-group" style={{ marginBottom: 0 }}>
                  <label className="form-label" htmlFor={`${fid}-type`}>Type</label>
                  <select id={`${fid}-type`} className="form-select" value={nodeType} onChange={(e) => setNodeType(e.target.value)}>
                    <option value="header">Header</option>
                    <option value="device">Device</option>
                    <option value="graph">Graph</option>
                  </select>
                </div>
                <div className="form-group" style={{ marginBottom: 0 }}>
                  <label className="form-label" htmlFor={`${fid}-sort`}>Sort</label>
                  <input id={`${fid}-sort`} className="form-input" type="number" value={sortOrder} onChange={(e) => setSortOrder(e.target.value)} style={{ width: 80 }} />
                </div>
                <button type="submit" className="btn btn-primary btn-sm" disabled={createNodeMut.isPending}>
                  {createNodeMut.isPending ? 'Adding…' : 'Add'}
                </button>
                <button type="button" className="btn btn-secondary btn-sm" onClick={() => setAddingNode(false)}>Cancel</button>
              </form>
            ) : (
              <button className="btn btn-sm btn-primary" style={{ marginTop: '0.5rem' }} onClick={() => setAddingNode(true)}>+ Add Node</button>
            )}
          </>
        );
      })()}
    </Modal>
  );
}
