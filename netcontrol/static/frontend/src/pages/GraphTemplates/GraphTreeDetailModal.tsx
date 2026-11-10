import { useMemo, useState } from 'react';

import { useInventoryGroups } from '@/api/compliance';
import { Callout } from '@/components/Callout';
import { DeleteButton } from '@/components/DeleteButton';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  useDeleteGraphTreeNode,
  useGraphTree,
  useHostGraphs,
  type GraphTreeNode,
} from '@/api/graphTemplates';

import { GraphTreeNodeModal, type TreeHostOption } from './GraphTreeNodeModal';
import { hostGraphLabel, nodeDescendantIds, orderTreeNodes } from './helpers';

interface Props {
  treeId: number | null;
  onClose: () => void;
}

/** The graph a `graph` node points at; one request per host, shared by its rows. */
function GraphTargetLabel({ hostId, graphId }: { hostId: number; graphId: number }) {
  const q = useHostGraphs(hostId);
  const g = q.data?.host_graphs.find((x) => x.id === graphId);
  if (g) return <>{hostGraphLabel(g)}</>;
  if (q.isPending) return <span className="text-muted">…</span>;
  return <span className="text-muted">Graph #{graphId}{q.data ? ' (missing)' : ''}</span>;
}

export function GraphTreeDetailModal({ treeId, onClose }: Props) {
  const { confirm, alert } = useDialogs();
  const isOpen = treeId != null;
  const query = useGraphTree(treeId);
  const inventory = useInventoryGroups(true);
  const deleteNodeMut = useDeleteGraphTreeNode();
  // The node dialog: 'new' to add one, a node to edit it, null when closed.
  const [nodeForm, setNodeForm] = useState<GraphTreeNode | 'new' | null>(null);

  const hosts: TreeHostOption[] | null = useMemo(
    () => (inventory.data ? inventory.data.flatMap((g) => g.hosts ?? []) : null),
    [inventory.data],
  );
  const hostName = (id: number) => hosts?.find((h) => h.id === id)?.hostname ?? `Host #${id}`;

  const nodes = useMemo(() => query.data?.nodes ?? [], [query.data]);
  const ordered = useMemo(() => orderTreeNodes(nodes), [nodes]);

  async function handleDeleteNode(node: GraphTreeNode) {
    if (treeId == null) return;
    const below = nodeDescendantIds(nodes, node.id).size;
    const name = node.title || `Node #${node.id}`;
    if (
      !(await confirm({
        title: 'Delete node',
        message: below
          ? `Delete node "${name}"? Its ${below} child node${below === 1 ? '' : 's'} will be removed too.`
          : `Delete node "${name}"?`,
        confirmLabel: 'Delete',
      }))
    )
      return;
    deleteNodeMut.mutate(
      { treeId, nodeId: node.id },
      { onError: (err) => { void alert({ message: (err as Error).message, variant: 'error' }); } },
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
      {query.data && (
        <>
          <p>{query.data.description || ''}</p>
          {inventory.error && (
            <Callout tone="warning">
              The inventory could not be loaded ({(inventory.error as Error).message}), so device and graph nodes cannot be pointed at a host. Header nodes can still be managed.
            </Callout>
          )}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h4>Nodes ({nodes.length})</h4>
            <button type="button" className="btn btn-sm btn-primary" onClick={() => setNodeForm('new')}>+ Add Node</button>
          </div>
          {nodes.length ? (
            <table className="data-table">
              <thead><tr><th>Title</th><th>Type</th><th>Target</th><th>Sort</th><th>Actions</th></tr></thead>
              <tbody>
                {ordered.map(({ item: n, depth }) => {
                  const name = n.title || `Node #${n.id}`;
                  return (
                    <tr key={n.id}>
                      <td style={{ paddingLeft: `calc(0.75rem + ${depth * 1.25}rem)` }}>
                        {depth > 0 && <span className="text-muted" aria-hidden="true">└ </span>}
                        {n.title || '-'}
                      </td>
                      <td><span className="badge badge-secondary">{n.node_type}</span></td>
                      <td>
                        {n.node_type === 'header' || n.host_id == null ? (
                          <span className="text-muted">-</span>
                        ) : n.node_type === 'graph' && n.graph_id != null ? (
                          <>{hostName(n.host_id)} / <GraphTargetLabel hostId={n.host_id} graphId={n.graph_id} /></>
                        ) : (
                          hostName(n.host_id)
                        )}
                      </td>
                      <td>{n.sort_order}</td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        <button
                          type="button"
                          className="btn btn-sm btn-secondary"
                          onClick={() => setNodeForm(n)}
                          aria-label={`Edit node ${name}`}
                        >
                          Edit
                        </button>{' '}
                        <DeleteButton
                          onClick={() => handleDeleteNode(n)}
                          disabled={deleteNodeMut.isPending}
                          busy={deleteNodeMut.isPending && deleteNodeMut.variables?.nodeId === n.id}
                          aria-label={`Delete node ${name}`}
                        />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          ) : <EmptyState compact message="No nodes yet. Add nodes to organize your graph hierarchy." />}
        </>
      )}

      {treeId != null && nodeForm != null && (
        <GraphTreeNodeModal
          key={nodeForm === 'new' ? 'new' : nodeForm.id}
          treeId={treeId}
          node={nodeForm === 'new' ? null : nodeForm}
          nodes={nodes}
          hosts={inventory.isPending ? [] : hosts}
          onClose={() => setNodeForm(null)}
        />
      )}
    </Modal>
  );
}
