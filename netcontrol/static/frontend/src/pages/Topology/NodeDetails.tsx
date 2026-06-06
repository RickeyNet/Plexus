import { useMemo, useState } from 'react';

import {
  type StpState,
  type TopologyEdge,
  type TopologyNode,
  useUpdateHostCategory,
} from '@/api/topology';
import {
  type HostAuditFinding,
  type InterfaceErrorRow,
  type InterfaceInventoryRow,
  type VlanDefinitionRow,
  type MacAddressRow,
  type ArpRow,
  useHostAuditFindings,
  useHostConfigBackups,
  useHostInterfaceErrors,
  useHostInterfaceInventory,
  useHostMacArp,
  useHostVlans,
} from '@/api/host-details';
import { useConfigBackupDetail } from '@/api/configuration';
import { Modal } from '@/components/Modal';
import { abbreviateInterface, formatBps, stpPortKey } from './helpers';

interface Props {
  node: TopologyNode;
  edges: TopologyEdge[];
  allNodes: TopologyNode[];
  stpStateByPort: Map<string, StpState>;
  onClose: () => void;
  onAddToInventory: (node: TopologyNode) => void;
  onCategoryUpdated: (hostId: number, newCategory: string) => void;
}

type TabKey =
  | 'overview'
  | 'interfaces'
  | 'vlans'
  | 'mac'
  | 'config'
  | 'errors'
  | 'audit';

const TABS: { key: TabKey; label: string }[] = [
  { key: 'overview', label: 'Overview' },
  { key: 'interfaces', label: 'Interfaces' },
  { key: 'vlans', label: 'VLANs' },
  { key: 'mac', label: 'MAC/ARP' },
  { key: 'config', label: 'Config' },
  { key: 'errors', label: 'Errors' },
  { key: 'audit', label: 'Audit' },
];

const SEVERITY_BADGE: Record<HostAuditFinding['severity'], string> = {
  critical: 'badge-danger',
  high: 'badge-danger',
  medium: 'badge-warning',
  low: 'badge-info',
  info: 'badge-muted',
};

export function NodeDetails({
  node,
  edges,
  allNodes,
  stpStateByPort,
  onClose,
  onAddToInventory,
  onCategoryUpdated,
}: Props) {
  const [activeTab, setActiveTab] = useState<TabKey>('overview');

  // Reset to overview whenever the operator picks a different node
  const [prevNodeId, setPrevNodeId] = useState(node.id);
  if (node.id !== prevNodeId) {
    setPrevNodeId(node.id);
    setActiveTab('overview');
  }

  // Tabs other than overview are only meaningful for inventory devices --
  // the data sources are keyed by host_id and unknown nodes don't have one.
  const hostId = node.in_inventory ? Number(node.id) : null;

  return (
    <aside
      style={{
        position: 'absolute',
        top: '0.75rem',
        right: '0.75rem',
        width: 380,
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
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '0.5rem',
        }}
      >
        <h4 style={{ margin: 0 }}>{node.label || 'Unknown'}</h4>
        <button
          type="button"
          className="modal-close"
          onClick={onClose}
          style={{ fontSize: '1.2rem' }}
        >
          ×
        </button>
      </div>

      <TabBar
        active={activeTab}
        onChange={setActiveTab}
        disabledNonOverview={hostId == null}
      />

      <div style={{ marginTop: '0.6rem' }}>
        {activeTab === 'overview' && (
          <OverviewTab
            node={node}
            edges={edges}
            allNodes={allNodes}
            stpStateByPort={stpStateByPort}
            onAddToInventory={onAddToInventory}
            onCategoryUpdated={onCategoryUpdated}
          />
        )}
        {activeTab === 'interfaces' && hostId != null && (
          <InterfacesTab hostId={hostId} />
        )}
        {activeTab === 'vlans' && hostId != null && <VlansTab hostId={hostId} />}
        {activeTab === 'mac' && hostId != null && <MacArpTab hostId={hostId} />}
        {activeTab === 'config' && hostId != null && (
          <ConfigTab hostId={hostId} />
        )}
        {activeTab === 'errors' && hostId != null && (
          <ErrorsTab hostId={hostId} />
        )}
        {activeTab === 'audit' && hostId != null && <AuditTab hostId={hostId} />}
      </div>
    </aside>
  );
}

// ── Tab bar ────────────────────────────────────────────────────────────────

function TabBar(props: {
  active: TabKey;
  onChange: (t: TabKey) => void;
  disabledNonOverview: boolean;
}) {
  return (
    <div
      style={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: '0.2rem',
        borderBottom: '1px solid var(--border)',
        paddingBottom: '0.3rem',
      }}
    >
      {TABS.map((t) => {
        const disabled =
          t.key !== 'overview' && props.disabledNonOverview;
        const isActive = props.active === t.key;
        return (
          <button
            key={t.key}
            type="button"
            onClick={() => !disabled && props.onChange(t.key)}
            disabled={disabled}
            style={{
              fontSize: '0.75rem',
              padding: '0.2rem 0.55rem',
              border: '1px solid transparent',
              borderBottom: isActive
                ? '2px solid var(--accent, #4d9bff)'
                : '2px solid transparent',
              background: isActive
                ? 'var(--surface-hover, rgba(255,255,255,0.04))'
                : 'transparent',
              color: disabled ? 'var(--text-muted)' : 'inherit',
              cursor: disabled ? 'not-allowed' : 'pointer',
              borderRadius: '0.2rem 0.2rem 0 0',
            }}
          >
            {t.label}
          </button>
        );
      })}
    </div>
  );
}

// ── Tab content: Overview (original NodeDetails body) ──────────────────────

function OverviewTab(props: {
  node: TopologyNode;
  edges: TopologyEdge[];
  allNodes: TopologyNode[];
  stpStateByPort: Map<string, StpState>;
  onAddToInventory: (node: TopologyNode) => void;
  onCategoryUpdated: (hostId: number, newCategory: string) => void;
}) {
  const { node, edges, allNodes, stpStateByPort, onAddToInventory, onCategoryUpdated } = props;
  const [category, setCategory] = useState(node.device_category ?? '');
  const [error, setError] = useState<string | null>(null);
  const updateCategory = useUpdateHostCategory();

  const [prevNodeKey, setPrevNodeKey] = useState(`${node.id}|${node.device_category ?? ''}`);
  const nodeKey = `${node.id}|${node.device_category ?? ''}`;
  if (nodeKey !== prevNodeKey) {
    setPrevNodeKey(nodeKey);
    setCategory(node.device_category ?? '');
    setError(null);
  }

  const connectedEdges = edges.filter(
    (e) => e.from === node.id || e.to === node.id,
  );

  async function handleCategoryChange(value: string) {
    setCategory(value);
    setError(null);
    try {
      await updateCategory.mutateAsync({
        hostId: Number(node.id),
        category: value,
      });
      onCategoryUpdated(Number(node.id), value);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'auto 1fr',
          gap: '0.35rem 0.75rem',
          fontSize: '0.85rem',
          alignItems: 'center',
        }}
      >
        <span className="text-muted">IP</span>
        <span>{node.ip || 'N/A'}</span>
        <span className="text-muted">Type</span>
        <span>{node.device_type || 'unknown'}</span>
        <span className="text-muted">Role</span>
        {node.in_inventory ? (
          <select
            className="form-select"
            style={{ fontSize: '0.8rem', padding: '0.15rem 0.3rem' }}
            value={category}
            onChange={(e) => handleCategoryChange(e.target.value)}
            disabled={updateCategory.isPending}
          >
            {['', 'router', 'switch', 'firewall', 'wireless', 'wlc', 'phone', 'server'].map((c) => (
              <option key={c} value={c}>{c || '(auto)'}</option>
            ))}
          </select>
        ) : (
          <span>{category || 'unknown'}</span>
        )}
        {node.model && (
          <>
            <span className="text-muted">Model</span>
            <span>{node.model}</span>
          </>
        )}
        <span className="text-muted">Status</span>
        <span className={`badge badge-${node.status === 'up' ? 'success' : node.status === 'down' ? 'danger' : 'secondary'}`}>{node.status || 'unknown'}</span>
        {node.group_name && (
          <>
            <span className="text-muted">Group</span>
            <span>{node.group_name}</span>
          </>
        )}
        <span className="text-muted">In Inventory</span>
        <span>{node.in_inventory ? 'Yes' : 'No'}</span>
        {node.platform && (
          <>
            <span className="text-muted">Platform</span>
            <span>{node.platform}</span>
          </>
        )}
      </div>
      {error && (
        <div style={{ color: 'var(--danger)', fontSize: '0.8rem', marginTop: '0.4rem' }}>
          {error}
        </div>
      )}

      {connectedEdges.length > 0 && (
        <>
          <h5 style={{ margin: '0.85rem 0 0.4rem' }}>
            Connections ({connectedEdges.length})
          </h5>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {connectedEdges.map((edge) => {
              const isSource = edge.from === node.id;
              const peerId = isSource ? edge.to : edge.from;
              const peer = allNodes.find((n) => n.id === peerId);
              const peerLabel = peer?.label ?? String(peerId);
              const proto = (edge.protocol ?? 'L2').toUpperCase();
              const util = edge.utilization;
              const stpKey = stpPortKey(edge.from_host_id ?? edge.from, edge.source_interface);
              const stp = stpStateByPort.get(stpKey);
              return (
                <div
                  key={String(edge.id)}
                  style={{
                    fontSize: '0.78rem',
                    padding: '0.4rem 0.55rem',
                    background: 'var(--bg-secondary)',
                    borderRadius: '0.3rem',
                  }}
                >
                  <div style={{ fontWeight: 500 }}>{peerLabel}</div>
                  <div className="text-muted" style={{ fontSize: '0.72rem' }}>
                    {abbreviateInterface(edge.source_interface) || '-'} ↔{' '}
                    {abbreviateInterface(edge.target_interface) || '-'} · {proto}
                  </div>
                  {util && (
                    <div
                      style={{
                        fontSize: '0.7rem',
                        marginTop: '0.25rem',
                        padding: '0.1rem 0.35rem',
                        borderRadius: '0.2rem',
                        display: 'inline-block',
                        background:
                          util.utilization_pct > 75
                            ? 'rgba(244,67,54,0.2)'
                            : util.utilization_pct > 50
                            ? 'rgba(255,235,59,0.15)'
                            : 'rgba(76,175,80,0.15)',
                        color:
                          util.utilization_pct > 75
                            ? '#ef5350'
                            : util.utilization_pct > 50
                            ? '#fdd835'
                            : '#66bb6a',
                      }}
                    >
                      {util.utilization_pct}% ({formatBps(util.in_bps)} in /{' '}
                      {formatBps(util.out_bps)} out)
                    </div>
                  )}
                  {stp && (
                    <div
                      style={{
                        fontSize: '0.7rem',
                        marginTop: '0.25rem',
                        padding: '0.1rem 0.35rem',
                        background: 'rgba(67,160,71,0.14)',
                        color: '#81c784',
                        borderRadius: '0.2rem',
                        display: 'inline-block',
                      }}
                    >
                      STP {stp.port_state ?? 'unknown'}
                      {stp.port_role ? '/' + stp.port_role : ''} VLAN {stp.vlan_id ?? ''}
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
    </>
  );
}

// ── Tab content: Interfaces ────────────────────────────────────────────────

function InterfacesTab({ hostId }: { hostId: number }) {
  const q = useHostInterfaceInventory(hostId);
  if (q.isPending) return <Loading />;
  if (q.error) return <ErrorRow error={q.error} />;
  const rows = q.data?.interfaces ?? [];
  if (rows.length === 0) return <Empty msg="No interface inventory collected yet." />;

  return (
    <CompactTable
      columns={['Port', 'Admin', 'Oper', 'Speed', 'Duplex', 'VLAN', 'Description']}
      rows={rows.map((r: InterfaceInventoryRow) => [
        abbreviateInterface(r.name) || `if${r.if_index}`,
        <StateBadge value={r.admin_state} />,
        <StateBadge value={r.oper_state} />,
        r.speed_mbps ? `${r.speed_mbps} Mbps` : '-',
        r.duplex || '-',
        r.access_vlan
          ? String(r.access_vlan)
          : r.trunk_vlans
          ? `trunk (${truncateList(r.trunk_vlans)})`
          : '-',
        r.description || '-',
      ])}
    />
  );
}

// ── Tab content: VLANs ─────────────────────────────────────────────────────

function VlansTab({ hostId }: { hostId: number }) {
  const q = useHostVlans(hostId);
  if (q.isPending) return <Loading />;
  if (q.error) return <ErrorRow error={q.error} />;
  const rows = q.data?.vlans ?? [];
  if (rows.length === 0) return <Empty msg="No VLAN definitions collected yet." />;

  return (
    <CompactTable
      columns={['VLAN', 'Name', 'State']}
      rows={rows.map((r: VlanDefinitionRow) => [
        String(r.vlan_id),
        r.name || '-',
        <StateBadge value={r.state} />,
      ])}
    />
  );
}

// ── Tab content: MAC / ARP ─────────────────────────────────────────────────

function MacArpTab({ hostId }: { hostId: number }) {
  const q = useHostMacArp(hostId);
  if (q.isPending) return <Loading />;
  if (q.error) return <ErrorRow error={q.error} />;
  const macs = q.data?.mac_table ?? [];
  const arps = q.data?.arp_table ?? [];
  if (macs.length === 0 && arps.length === 0) {
    return <Empty msg="No MAC or ARP entries collected yet." />;
  }

  return (
    <>
      {macs.length > 0 && (
        <>
          <SubHeading label={`MAC table (${macs.length})`} />
          <CompactTable
            columns={['MAC', 'VLAN', 'Port', 'Type']}
            rows={macs.slice(0, 200).map((m: MacAddressRow) => [
              m.mac_address,
              m.vlan ? String(m.vlan) : '-',
              abbreviateInterface(m.port_name) || '-',
              m.entry_type || '-',
            ])}
            footer={macs.length > 200 ? `Showing first 200 of ${macs.length}` : undefined}
          />
        </>
      )}
      {arps.length > 0 && (
        <>
          <SubHeading label={`ARP cache (${arps.length})`} />
          <CompactTable
            columns={['IP', 'MAC', 'Interface']}
            rows={arps.slice(0, 200).map((a: ArpRow) => [
              a.ip_address,
              a.mac_address,
              abbreviateInterface(a.interface_name) || '-',
            ])}
            footer={arps.length > 200 ? `Showing first 200 of ${arps.length}` : undefined}
          />
        </>
      )}
    </>
  );
}

// ── Tab content: Config backups ────────────────────────────────────────────

function ConfigTab({ hostId }: { hostId: number }) {
  const list = useHostConfigBackups(hostId, 1);
  const latest = list.data?.[0];
  const detail = useConfigBackupDetail(latest?.id ?? null);
  const [expanded, setExpanded] = useState(false);

  if (list.isPending) return <Loading />;
  if (list.error) return <ErrorRow error={list.error} />;
  if (!latest) return <Empty msg="No config backups for this device." />;

  const configText = detail.data?.config_text ?? '';
  const capturedLabel = latest.captured_at
    ? new Date(latest.captured_at).toLocaleString()
    : '-';

  return (
    <>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '0.5rem',
          marginBottom: '0.4rem',
          fontSize: '0.72rem',
          color: 'var(--text-muted)',
        }}
      >
        <span>
          Captured {capturedLabel}
          {latest.config_length != null ? ` · ${latest.config_length} B` : ''}
          {latest.capture_method ? ` · ${latest.capture_method}` : ''}
        </span>
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          onClick={() => setExpanded(true)}
          disabled={!configText}
        >
          Expand
        </button>
      </div>

      {detail.isPending ? (
        <Loading />
      ) : detail.error ? (
        <ErrorRow error={detail.error} />
      ) : !configText ? (
        <Empty msg="Backup has no config text." />
      ) : (
        <pre
          style={{
            background: 'var(--bg, #0d1117)',
            border: '1px solid var(--border)',
            borderRadius: '0.35rem',
            padding: '0.5rem',
            fontFamily:
              'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
            fontSize: '0.72rem',
            lineHeight: 1.4,
            maxHeight: 280,
            overflow: 'auto',
            whiteSpace: 'pre',
            margin: 0,
          }}
        >
          {configText}
        </pre>
      )}

      <Modal
        isOpen={expanded}
        onClose={() => setExpanded(false)}
        title={`Running config — captured ${capturedLabel}`}
        size="large"
      >
        <pre
          style={{
            background: 'var(--bg, #0d1117)',
            border: '1px solid var(--border)',
            borderRadius: '0.35rem',
            padding: '0.75rem',
            fontFamily:
              'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
            fontSize: '0.8rem',
            lineHeight: 1.45,
            maxHeight: '75vh',
            overflow: 'auto',
            whiteSpace: 'pre',
            margin: 0,
          }}
        >
          {configText}
        </pre>
      </Modal>
    </>
  );
}

// ── Tab content: Interface errors ──────────────────────────────────────────

function ErrorsTab({ hostId }: { hostId: number }) {
  const q = useHostInterfaceErrors(hostId, 1);
  if (q.isPending) return <Loading />;
  if (q.error) return <ErrorRow error={q.error} />;
  const ifaces = q.data?.interfaces ?? [];
  // Only show interfaces that actually saw errors in the window
  const errored = ifaces.filter((row: InterfaceErrorRow) =>
    Object.values(row.metrics).some((m) => (m.max_value ?? 0) > 0),
  );
  if (errored.length === 0) {
    return <Empty msg="No interface errors in the last 24h." />;
  }

  return (
    <CompactTable
      columns={['Port', 'Metric', 'Avg', 'Peak']}
      rows={errored.flatMap((row: InterfaceErrorRow) =>
        Object.entries(row.metrics)
          .filter(([, m]) => (m.max_value ?? 0) > 0)
          .map(([metric, m]) => [
            abbreviateInterface(row.if_name) || `if${row.if_index ?? '?'}`,
            metric,
            m.avg_value != null ? String(m.avg_value) : '-',
            m.max_value != null ? String(m.max_value) : '-',
          ]),
      )}
      footer={
        q.data && q.data.active_events > 0
          ? `${q.data.active_events} active event(s)`
          : undefined
      }
    />
  );
}

// ── Tab content: Audit findings ────────────────────────────────────────────

function AuditTab({ hostId }: { hostId: number }) {
  const q = useHostAuditFindings(hostId, 50);
  // Only show the latest run's findings (rows are returned id-DESC, so the
  // top run_id is the most recent). Older findings would clutter the pane.
  const { latestRunId, latest } = useMemo(() => {
    const rows = q.data?.findings ?? [];
    const runId = rows[0]?.run_id;
    return { latestRunId: runId, latest: rows.filter((r) => r.run_id === runId) };
  }, [q.data]);

  if (q.isPending) return <Loading />;
  if (q.error) return <ErrorRow error={q.error} />;
  if (latest.length === 0) return <Empty msg="No audit findings for this device." />;

  return (
    <>
      <div className="text-muted" style={{ fontSize: '0.75rem', marginBottom: '0.4rem' }}>
        Latest run #{latestRunId} · {latest.length} finding{latest.length === 1 ? '' : 's'}
      </div>
      <CompactTable
        columns={['Severity', 'Rule', 'Title']}
        rows={latest.map((f: HostAuditFinding) => [
          <span className={`badge ${SEVERITY_BADGE[f.severity]}`}>{f.severity}</span>,
          <code style={{ fontSize: '0.7rem' }}>{f.rule_id}</code>,
          f.title,
        ])}
      />
    </>
  );
}

// ── Shared atoms ───────────────────────────────────────────────────────────

function Loading() {
  return (
    <p className="text-muted" style={{ fontSize: '0.78rem' }}>
      Loading…
    </p>
  );
}

function ErrorRow({ error }: { error: unknown }) {
  return (
    <p style={{ color: 'var(--danger)', fontSize: '0.78rem' }}>
      {(error as Error).message}
    </p>
  );
}

function Empty({ msg }: { msg: string }) {
  return (
    <p className="text-muted" style={{ fontSize: '0.78rem' }}>
      {msg}
    </p>
  );
}

function SubHeading({ label }: { label: string }) {
  return (
    <h6
      style={{
        margin: '0.6rem 0 0.3rem',
        fontSize: '0.72rem',
        textTransform: 'uppercase',
        letterSpacing: '0.05em',
        color: 'var(--text-muted)',
      }}
    >
      {label}
    </h6>
  );
}

function StateBadge({ value }: { value: string }) {
  const v = (value || '').toLowerCase();
  let cls = 'badge-muted';
  if (v === 'up' || v === 'active' || v === 'operational') cls = 'badge-success';
  else if (v === 'down' || v === 'shutdown' || v === 'suspended') cls = 'badge-danger';
  else if (v === 'testing' || v === 'unknown') cls = 'badge-warning';
  return <span className={`badge ${cls}`}>{value || '-'}</span>;
}

function CompactTable(props: {
  columns: string[];
  rows: React.ReactNode[][];
  footer?: string;
}) {
  return (
    <>
      <table
        className="data-table"
        style={{ fontSize: '0.75rem', width: '100%' }}
      >
        <thead>
          <tr>
            {props.columns.map((c) => (
              <th key={c} style={{ textAlign: 'left' }}>
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {props.rows.map((cells, i) => (
            <tr key={i}>
              {cells.map((cell, j) => (
                <td key={j}>{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {props.footer && (
        <div
          className="text-muted"
          style={{ fontSize: '0.7rem', marginTop: '0.3rem' }}
        >
          {props.footer}
        </div>
      )}
    </>
  );
}

function truncateList(csv: string, max = 8): string {
  const parts = csv.split(',').map((s) => s.trim()).filter(Boolean);
  if (parts.length <= max) return parts.join(',');
  return `${parts.slice(0, max).join(',')}…`;
}
