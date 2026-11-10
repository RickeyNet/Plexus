import { useId, useMemo, useState, type FormEvent } from 'react';

import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import {
  useCreateGraphTreeNode,
  useHostGraphs,
  useUpdateGraphTreeNode,
  type GraphTreeNode,
  type GraphTreeNodeType,
} from '@/api/graphTemplates';
import { parseBoundedInt } from '@/lib/numberInput';

import {
  hostGraphLabel,
  nodeDescendantIds,
  nodePayload,
  orderTreeNodes,
  validateNodeForm,
  type NodeFormErrors,
} from './helpers';

export interface TreeHostOption {
  id: number;
  hostname: string;
  ip_address?: string | null;
}

interface Props {
  treeId: number;
  /** The node being edited, or null to add one. */
  node: GraphTreeNode | null;
  /** Every node of the tree, for the parent choices. */
  nodes: GraphTreeNode[];
  /** Inventory hosts; null when the inventory could not be loaded. */
  hosts: TreeHostOption[] | null;
  onClose: () => void;
}

const NODE_TYPES: { value: GraphTreeNodeType; label: string }[] = [
  { value: 'header', label: 'Header' },
  { value: 'device', label: 'Device' },
  { value: 'graph', label: 'Graph' },
];

function asNodeType(v: string | undefined): GraphTreeNodeType {
  return v === 'device' || v === 'graph' ? v : 'header';
}

/**
 * Add / edit one graph tree node. Mount it with a `key` per node so the
 * fields start from that node.
 */
export function GraphTreeNodeModal({ treeId, node, nodes, hosts, onClose }: Props) {
  const formId = useId();
  const createMut = useCreateGraphTreeNode();
  const updateMut = useUpdateGraphTreeNode();

  const [title, setTitle] = useState(node?.title ?? '');
  const [nodeType, setNodeType] = useState<GraphTreeNodeType>(asNodeType(node?.node_type));
  const [parentId, setParentId] = useState<number | null>(node?.parent_node_id ?? null);
  const [sortOrder, setSortOrder] = useState(String(node?.sort_order ?? 0));
  const [hostId, setHostId] = useState<number | null>(node?.host_id ?? null);
  const [graphId, setGraphId] = useState<number | null>(node?.graph_id ?? null);
  const [errors, setErrors] = useState<NodeFormErrors>({});
  const [saveError, setSaveError] = useState<string | null>(null);

  const hostGraphs = useHostGraphs(nodeType === 'graph' ? hostId : null);
  const graphList = hostGraphs.data?.host_graphs ?? [];

  // A node cannot sit under itself or anything below it.
  const parentChoices = useMemo(() => {
    const excluded = node ? nodeDescendantIds(nodes, node.id).add(node.id) : new Set<number>();
    return orderTreeNodes(nodes).filter((e) => !excluded.has(e.item.id));
  }, [nodes, node]);

  const hostChoices = useMemo(() => {
    const list = hosts ?? [];
    // Keep the saved host selectable when the inventory list lacks it.
    if (hostId != null && !list.some((h) => h.id === hostId)) {
      return [...list, { id: hostId, hostname: `Host #${hostId}` }];
    }
    return list;
  }, [hosts, hostId]);

  const selectedHost = hostChoices.find((h) => h.id === hostId);
  const selectedGraph = graphList.find((g) => g.id === graphId);
  const defaultTitle =
    nodeType === 'device' ? selectedHost?.hostname ?? ''
    : nodeType === 'graph' ? (selectedGraph ? hostGraphLabel(selectedGraph) : '')
    : '';

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSaveError(null);
    const values = {
      title,
      nodeType,
      sortOrder: parseBoundedInt(sortOrder, -9999, 9999, node?.sort_order ?? 0),
      parentId,
      hostId,
      graphId,
    };
    const found = validateNodeForm(values, defaultTitle);
    setErrors(found);
    if (Object.keys(found).length) return;
    const data = nodePayload(values, defaultTitle);
    const onError = (err: unknown) => { setSaveError((err as Error).message); };
    if (node) {
      updateMut.mutate({ treeId, nodeId: node.id, data }, { onSuccess: onClose, onError });
    } else {
      createMut.mutate({ treeId, data }, { onSuccess: onClose, onError });
    }
  }

  const pending = createMut.isPending || updateMut.isPending;
  const noInventory = hosts == null;

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={node ? 'Edit Node' : 'Add Node'}
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={pending}>
            {pending ? 'Saving…' : node ? 'Save' : 'Add'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        {noInventory && (
          <Callout tone="warning">
            The inventory could not be loaded, so hosts cannot be chosen. Header nodes can still be added and edited.
          </Callout>
        )}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-type`}>Type</label>
            <select
              id={`${formId}-type`}
              className="form-select"
              value={nodeType}
              onChange={(e) => {
                setNodeType(asNodeType(e.target.value));
                setErrors({});
              }}
            >
              {NODE_TYPES.map((t) => (
                <option
                  key={t.value}
                  value={t.value}
                  // Without the inventory a host cannot be picked; keep a saved type selectable.
                  disabled={noInventory && t.value !== 'header' && t.value !== asNodeType(node?.node_type)}
                >
                  {t.label}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-parent`}>Parent</label>
            <select
              id={`${formId}-parent`}
              className="form-select"
              value={parentId ?? ''}
              onChange={(e) => setParentId(e.target.value ? Number(e.target.value) : null)}
            >
              <option value="">(Top level)</option>
              {parentChoices.map(({ item, depth }) => (
                <option key={item.id} value={item.id}>
                  {'  '.repeat(depth)}{item.title || `Node #${item.id}`}
                </option>
              ))}
            </select>
          </div>

          {nodeType !== 'header' && (
            <div className="form-group">
              <label className="form-label" htmlFor={`${formId}-host`}>Host</label>
              <select
                id={`${formId}-host`}
                className="form-select"
                value={hostId ?? ''}
                onChange={(e) => {
                  setHostId(e.target.value ? Number(e.target.value) : null);
                  setGraphId(null);
                  setErrors((prev) => ({ ...prev, host: undefined, graph: undefined }));
                }}
                aria-invalid={!!errors.host}
              >
                <option value="">Select a host…</option>
                {hostChoices.map((h) => (
                  <option key={h.id} value={h.id}>
                    {h.hostname}{h.ip_address ? ` (${h.ip_address})` : ''}
                  </option>
                ))}
              </select>
              <FieldError>{errors.host}</FieldError>
            </div>
          )}

          {nodeType === 'graph' && (
            <div className="form-group">
              <label className="form-label" htmlFor={`${formId}-graph`}>Graph</label>
              <select
                id={`${formId}-graph`}
                className="form-select"
                value={graphId ?? ''}
                onChange={(e) => {
                  setGraphId(e.target.value ? Number(e.target.value) : null);
                  setErrors((prev) => ({ ...prev, graph: undefined }));
                }}
                disabled={hostId == null || hostGraphs.isPending}
                aria-invalid={!!errors.graph}
              >
                <option value="">
                  {hostId == null ? 'Choose a host first'
                    : hostGraphs.isPending ? 'Loading graphs…'
                    : graphList.length ? 'Select a graph…' : 'This host has no graphs'}
                </option>
                {graphList.map((g) => (
                  <option key={g.id} value={g.id}>{hostGraphLabel(g)}</option>
                ))}
                {graphId != null && !hostGraphs.isPending && !selectedGraph && (
                  <option value={graphId}>{hostGraphs.error ? `Graph #${graphId}` : `Graph #${graphId} (no longer on this host)`}</option>
                )}
              </select>
              {hostGraphs.error && <FieldError>Failed to load graphs: {(hostGraphs.error as Error).message}</FieldError>}
              <FieldError>{errors.graph}</FieldError>
            </div>
          )}

          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-title`}>Title</label>
            <input
              id={`${formId}-title`}
              className="form-input"
              value={title}
              onChange={(e) => {
                setTitle(e.target.value);
                setErrors((prev) => ({ ...prev, title: undefined }));
              }}
              placeholder={defaultTitle || (nodeType === 'header' ? 'e.g. Branch sites' : '')}
              aria-invalid={!!errors.title}
            />
            {nodeType !== 'header' && (
              <p className="text-muted" style={{ fontSize: '0.8rem', margin: '0.25rem 0 0' }}>
                Leave blank to use the {nodeType === 'device' ? 'host name' : 'graph title'}.
              </p>
            )}
            <FieldError>{errors.title}</FieldError>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-sort`}>Sort Order</label>
            <input id={`${formId}-sort`} className="form-input" type="number" value={sortOrder} onChange={(e) => setSortOrder(e.target.value)} />
          </div>
        </div>
      </form>
    </Modal>
  );
}
