import { useState } from 'react';

import {
  type StpState,
  type TopologyEdge,
  type TopologyNode,
  useUpdateHostCategory,
} from '@/api/topology';
import { abbreviateInterface, formatBps } from './helpers';

interface Props {
  node: TopologyNode;
  edges: TopologyEdge[];
  allNodes: TopologyNode[];
  stpStateByPort: Map<string, StpState>;
  onClose: () => void;
  onAddToInventory: (node: TopologyNode) => void;
  onCategoryUpdated: (hostId: number, newCategory: string) => void;
}

const CATEGORY_OPTIONS = ['', 'router', 'switch', 'firewall', 'wireless', 'wlc', 'phone', 'server'];
const PROTO_LABEL: Record<string, string> = {
  cdp: 'CDP',
  lldp: 'LLDP',
  ospf: 'OSPF',
  bgp: 'BGP',
  'inferred-fdb': 'INFERRED',
};

export function NodeDetails({ node, edges, allNodes, stpStateByPort, onClose, onAddToInventory, onCategoryUpdated }: Props) {
  const [category, setCategory] = useState(node.device_category ?? '');
  const [error, setError] = useState<string | null>(null);
  const updateCategory = useUpdateHostCategory();

  const connectedEdges = edges.filter((e) => e.from === node.id || e.to === node.id);

  async function handleCategoryChange(value: string) {
    setCategory(value);
    setError(null);
    try {
      await updateCategory.mutateAsync({ hostId: Number(node.id), category: value });
      onCategoryUpdated(Number(node.id), value);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <aside
      style={{
        position: 'absolute',
        top: '0.75rem',
        right: '0.75rem',
        width: 320,
        maxHeight: 'calc(100% - 1.5rem)',
        background: 'var(--card-bg)',
        border: '1px solid var(--border)',
        borderRadius: '0.5rem',
        padding: '0.85rem',
        overflowY: 'auto',
        zIndex: 5,
        boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
        <h4 style={{ margin: 0 }}>{node.label || 'Unknown'}</h4>
        <button type="button" className="modal-close" onClick={onClose} style={{ fontSize: '1.2rem' }}>×</button>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '0.35rem 0.75rem', fontSize: '0.85rem', alignItems: 'center' }}>
        <span className="text-muted">IP</span><span>{node.ip || 'N/A'}</span>
        <span className="text-muted">Type</span><span>{node.device_type || 'unknown'}</span>
        <span className="text-muted">Role</span>
        {node.in_inventory ? (
          <select
            className="form-select"
            style={{ fontSize: '0.8rem', padding: '0.15rem 0.3rem' }}
            value={category}
            onChange={(e) => handleCategoryChange(e.target.value)}
            disabled={updateCategory.isPending}
          >
            {CATEGORY_OPTIONS.map((c) => (
              <option key={c} value={c}>{c || '(auto)'}</option>
            ))}
          </select>
        ) : (
          <span>{category || 'unknown'}</span>
        )}
        {node.model && (<><span className="text-muted">Model</span><span>{node.model}</span></>)}
        <span className="text-muted">Status</span>
        <span className={`badge badge-${node.status === 'up' ? 'success' : node.status === 'down' ? 'danger' : 'secondary'}`}>{node.status || 'unknown'}</span>
        {node.group_name && (<><span className="text-muted">Group</span><span>{node.group_name}</span></>)}
        <span className="text-muted">In Inventory</span><span>{node.in_inventory ? 'Yes' : 'No'}</span>
        {node.platform && (<><span className="text-muted">Platform</span><span>{node.platform}</span></>)}
      </div>
      {error && <div style={{ color: 'var(--danger)', fontSize: '0.8rem', marginTop: '0.4rem' }}>{error}</div>}

      {connectedEdges.length > 0 && (
        <>
          <h5 style={{ margin: '0.85rem 0 0.4rem' }}>Connections ({connectedEdges.length})</h5>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {connectedEdges.map((edge) => {
              const isSource = edge.from === node.id;
              const peerId = isSource ? edge.to : edge.from;
              const peer = allNodes.find((n) => n.id === peerId);
              const peerLabel = peer?.label ?? String(peerId);
              const proto = PROTO_LABEL[edge.protocol ?? ''] ?? (edge.protocol ?? 'L2').toUpperCase();
              const util = edge.utilization;
              const stpKey = `${edge.from_host_id ?? edge.from}|${(edge.source_interface ?? '').toLowerCase()}`;
              const stp = stpStateByPort.get(stpKey);
              return (
                <div key={String(edge.id)} style={{ fontSize: '0.78rem', padding: '0.4rem 0.55rem', background: 'var(--bg-secondary)', borderRadius: '0.3rem' }}>
                  <div style={{ fontWeight: 500 }}>{peerLabel}</div>
                  <div className="text-muted" style={{ fontSize: '0.72rem' }}>
                    {abbreviateInterface(edge.source_interface) || '-'} ↔ {abbreviateInterface(edge.target_interface) || '-'} · {proto}
                  </div>
                  {util && (
                    <div style={{
                      fontSize: '0.7rem',
                      marginTop: '0.25rem',
                      padding: '0.1rem 0.35rem',
                      borderRadius: '0.2rem',
                      display: 'inline-block',
                      background: util.utilization_pct > 75 ? 'rgba(244,67,54,0.2)' : util.utilization_pct > 50 ? 'rgba(255,235,59,0.15)' : 'rgba(76,175,80,0.15)',
                      color: util.utilization_pct > 75 ? '#ef5350' : util.utilization_pct > 50 ? '#fdd835' : '#66bb6a',
                    }}>
                      {util.utilization_pct}% ({formatBps(util.in_bps)} in / {formatBps(util.out_bps)} out)
                    </div>
                  )}
                  {stp && (
                    <div style={{
                      fontSize: '0.7rem',
                      marginTop: '0.25rem',
                      padding: '0.1rem 0.35rem',
                      background: 'rgba(67,160,71,0.14)',
                      color: '#81c784',
                      borderRadius: '0.2rem',
                      display: 'inline-block',
                    }}>
                      STP {stp.port_state ?? 'unknown'}{stp.port_role ? '/' + stp.port_role : ''} VLAN {stp.vlan_id ?? ''}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </>
      )}

      {!node.in_inventory && node.ip && (
        <button
          type="button"
          className="btn btn-primary btn-sm"
          style={{ marginTop: '1rem', width: '100%' }}
          onClick={() => onAddToInventory(node)}
        >
          Add to Inventory
        </button>
      )}
    </aside>
  );
}
