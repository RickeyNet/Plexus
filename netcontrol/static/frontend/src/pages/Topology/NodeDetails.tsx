import { useMemo, useRef, useState } from 'react';

import {
  type StpState,
  type TopologyEdge,
  type TopologyMerakiRef,
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
import {
  abbreviateInterface,
  DETAIL_CELL_STYLE,
  DETAILS_PANEL_MIN_WIDTH,
  draggedPanelWidth,
  formatBps,
  providerLabel,
  providerScopeName,
  providerSourceName,
  SCROLL_X_STYLE,
  stpPortKey,
} from './helpers';
import { useMerakiNodeDetails } from '@/api/meraki';
import { MerakiDetails } from './MerakiDetails';
import {
  type MerakiView,
  merakiViewSections,
  merakiViewsWithData,
  searchTerms,
  sectionsMatch,
} from './merakiHelpers';

interface Props {
  node: TopologyNode;
  edges: TopologyEdge[];
  allNodes: TopologyNode[];
  stpStateByPort: Map<string, StpState>;
  onClose: () => void;
  onAddToInventory: (node: TopologyNode) => void;
  onCategoryUpdated: (hostId: number, newCategory: string) => void;
  /** Active map search text, so matching Meraki rows can be highlighted. */
  searchText?: string;
}

// 'aws' is the secondary AWS tab of a node whose primary reference is another
// integration (a Meraki/Cato device that is also an EC2 instance).
type TabKey = 'overview' | MerakiView | 'aws' | 'config' | 'errors' | 'audit';

const TABS: { key: TabKey; label: string }[] = [
  { key: 'overview', label: 'Overview' },
  { key: 'meraki', label: 'Device' },
  { key: 'interfaces', label: 'Interfaces' },
  { key: 'vlans', label: 'VLANs' },
  { key: 'mac', label: 'MAC/ARP' },
  { key: 'routing', label: 'Routing' },
  { key: 'vpn', label: 'VPN' },
  { key: 'firewall', label: 'Firewall' },
  { key: 'switching', label: 'Switching' },
  { key: 'wireless', label: 'Wireless' },
  { key: 'aws', label: 'AWS' },
  { key: 'config', label: 'Config' },
  { key: 'errors', label: 'Errors' },
  { key: 'audit', label: 'Audit' },
];

// Tabs backed by inventory (SNMP/SSH) data, keyed by host id.
const INVENTORY_TABS: TabKey[] = ['interfaces', 'vlans', 'mac', 'config', 'errors', 'audit'];

/**
 * The AWS instance behind a node as a snapshot ref, when it is only a
 * secondary reference (the node's own `meraki` ref is another integration).
 */
function secondaryAwsRef(node: TopologyNode): TopologyMerakiRef | null {
  const instance = node.instance;
  if (!instance || node.meraki?.provider === instance.provider) return null;
  return {
    org_ref: instance.org_ref,
    node_id: instance.node_id,
    site_id: '',
    site_name: instance.vpc,
    kind: 'server',
    status: node.status ?? 'unknown',
    provider: 'aws',
    instance_id: instance.id,
    subnet: instance.subnet,
  };
}

// Width the operator dragged the details panel to, shared by every tab.
const PANEL_WIDTH_KEY = 'plexus.topology.detailsWidth';

function readStoredPanelWidth(): number | null {
  try {
    const width = Number(localStorage.getItem(PANEL_WIDTH_KEY) ?? NaN);
    return Number.isFinite(width) && width >= DETAILS_PANEL_MIN_WIDTH ? width : null;
  } catch {
    return null;
  }
}

function writeStoredPanelWidth(width: number | null): void {
  try {
    if (width == null) localStorage.removeItem(PANEL_WIDTH_KEY);
    else localStorage.setItem(PANEL_WIDTH_KEY, String(width));
  } catch {
    // Storage unavailable (private mode, quota): the width just isn't remembered.
  }
}

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
  searchText,
}: Props) {
  // A Meraki-only device has nothing behind the inventory tabs, so it opens
  // straight on its Meraki details.
  const initialTab: TabKey = node.meraki && !node.in_inventory ? 'meraki' : 'overview';
  const [activeTab, setActiveTab] = useState<TabKey>(initialTab);

  // Reset whenever the operator picks a different node
  const [prevNodeId, setPrevNodeId] = useState(node.id);
  if (node.id !== prevNodeId) {
    setPrevNodeId(node.id);
    setActiveTab(initialTab);
  }

  // Tabs other than overview are only meaningful for inventory devices --
  // the data sources are keyed by host_id and unknown nodes don't have one.
  const hostId = node.in_inventory ? Number(node.id) : null;
  // Each category of collected Meraki data gets its own tab, shown only when
  // the Dashboard reported something for it. (Same query MerakiDetails uses.)
  const merakiDetails = useMerakiNodeDetails(node.meraki?.org_ref ?? null, node.meraki?.node_id ?? null);
  const merakiData = node.meraki ? merakiDetails.data : undefined;
  // Until the details load, only the device summary tab is offered.
  const merakiViews: MerakiView[] = !node.meraki ? [] : merakiData ? merakiViewsWithData(merakiData) : ['meraki'];
  const highlightTerms = searchTerms(searchText ?? '');
  const awsRef = secondaryAwsRef(node);

  const tabs = TABS.filter((t) => {
    if (t.key === 'overview') return true;
    if (t.key === 'aws') return awsRef != null;
    if (INVENTORY_TABS.includes(t.key) && (hostId != null || !node.meraki)) return true;
    return merakiViews.includes(t.key as MerakiView);
  }).map((t) => {
    const fromMeraki = merakiViews.includes(t.key as MerakiView);
    const { sections, siteSections } =
      fromMeraki && merakiData
        ? merakiViewSections(merakiData, t.key as MerakiView)
        : { sections: [], siteSections: [] };
    return {
      ...t,
      // Without a host there is nothing behind an inventory tab.
      disabled: !fromMeraki && hostId == null && t.key !== 'overview' && t.key !== 'aws',
      // Points at the tabs holding rows that match the active map search.
      matched: sectionsMatch(sections, highlightTerms) || sectionsMatch(siteSections, highlightTerms),
    };
  });
  // A tab can go away once the details load (nothing collected for it).
  const shownTab: TabKey = tabs.some((t) => t.key === activeTab && !t.disabled) ? activeTab : 'overview';
  const merakiView = merakiViews.includes(shownTab as MerakiView) ? (shownTab as MerakiView) : null;
  const tabLabel = tabs.find((t) => t.key === shownTab)?.label ?? '';

  // The operator can drag the panel's left edge to widen it (wide tables on a
  // big monitor); the width is remembered and then used for every tab.
  const [customWidth, setCustomWidth] = useState<number | null>(readStoredPanelWidth);
  const [handleHot, setHandleHot] = useState(false);
  const asideRef = useRef<HTMLElement>(null);
  const dragRef = useRef<{
    startX: number;
    startWidth: number;
    mapWidth: number;
    /** Latest dragged width; null until the pointer actually moves. */
    width: number | null;
  } | null>(null);
  const panelWidth = customWidth ?? (merakiView || shownTab === 'aws' ? 460 : 380);

  function startResize(e: React.PointerEvent<HTMLDivElement>) {
    if (e.button !== 0) return;
    e.preventDefault();
    e.currentTarget.setPointerCapture(e.pointerId);
    const aside = asideRef.current;
    const map = aside?.offsetParent;
    dragRef.current = {
      startX: e.clientX,
      // The width on screen: a remembered width is capped by the map's width.
      startWidth: aside ? aside.getBoundingClientRect().width : panelWidth,
      mapWidth: map ? map.clientWidth : window.innerWidth,
      width: null,
    };
  }

  function moveResize(e: React.PointerEvent<HTMLDivElement>) {
    const drag = dragRef.current;
    if (!drag) return;
    drag.width = draggedPanelWidth(drag.startWidth, drag.startX, e.clientX, drag.mapWidth);
    setCustomWidth(drag.width);
  }

  function endResize() {
    const drag = dragRef.current;
    if (!drag) return;
    dragRef.current = null;
    // A plain click (or the first half of a double-click) leaves the width alone.
    if (drag.width != null) writeStoredPanelWidth(drag.width);
  }

  function resetWidth() {
    dragRef.current = null;
    setCustomWidth(null);
    writeStoredPanelWidth(null);
  }

  return (
    <aside
      ref={asideRef}
      style={{
        position: 'absolute',
        top: '0.75rem',
        right: '0.75rem',
        width: panelWidth,
        // A remembered width never pushes the panel past the map's left edge.
        maxWidth: 'calc(100% - 1.5rem)',
        maxHeight: 'calc(100% - 1.5rem)',
        display: 'flex',
        flexDirection: 'column',
        background: 'var(--card-bg)',
        border: '1px solid var(--border)',
        borderRadius: '0.5rem',
        overflow: 'hidden',
        zIndex: 5,
        boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
      }}
    >
      {/* Resize handle. The content scrolls in the inner div, not the aside, so
          the handle spans the panel's full height however far it is scrolled. */}
      <div
        aria-hidden
        title="Drag to resize, double-click to reset"
        onPointerDown={startResize}
        onPointerMove={moveResize}
        onPointerUp={endResize}
        onPointerCancel={endResize}
        onDoubleClick={resetWidth}
        onMouseEnter={() => setHandleHot(true)}
        onMouseLeave={() => setHandleHot(false)}
        style={{
          position: 'absolute',
          top: 0,
          bottom: 0,
          left: 0,
          width: 6,
          cursor: 'ew-resize',
          zIndex: 1,
          touchAction: 'none',
          background: handleHot ? 'var(--border)' : 'transparent',
        }}
      />
      <div style={{ padding: '0.85rem', overflowY: 'auto', minHeight: 0 }}>
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

        <TabBar tabs={tabs} active={shownTab} onChange={setActiveTab} />

        <div style={{ marginTop: '0.6rem' }}>
          {shownTab === 'overview' && (
            <OverviewTab
              node={node}
              edges={edges}
              allNodes={allNodes}
              stpStateByPort={stpStateByPort}
              onAddToInventory={onAddToInventory}
              onCategoryUpdated={onCategoryUpdated}
            />
          )}
          {shownTab === 'interfaces' && hostId != null && (
            <InterfacesTab hostId={hostId} />
          )}
          {shownTab === 'vlans' && hostId != null && <VlansTab hostId={hostId} />}
          {shownTab === 'mac' && hostId != null && <MacArpTab hostId={hostId} />}
          {shownTab === 'config' && hostId != null && (
            <ConfigTab hostId={hostId} />
          )}
          {shownTab === 'errors' && hostId != null && (
            <ErrorsTab hostId={hostId} />
          )}
          {shownTab === 'audit' && hostId != null && <AuditTab hostId={hostId} />}
          {merakiView && node.meraki && (
            <>
              {/* An inventory host that is also a Meraki device shows both sources. */}
              {hostId != null && INVENTORY_TABS.includes(merakiView) && (
                <SubHeading label={providerSourceName(node.meraki.provider)} />
              )}
              <MerakiDetails
                key={merakiView}
                meraki={node.meraki}
                highlight={searchText}
                view={merakiView}
                title={tabLabel}
              />
            </>
          )}
          {shownTab === 'aws' && awsRef && (
            <MerakiDetails key="aws" meraki={awsRef} highlight={searchText} view="all" title="AWS" />
          )}
        </div>
      </div>
    </aside>
  );
}

// ── Tab bar ────────────────────────────────────────────────────────────────

function TabBar(props: {
  tabs: { key: TabKey; label: string; disabled: boolean; matched: boolean }[];
  active: TabKey;
  onChange: (t: TabKey) => void;
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
      {props.tabs.map((t) => {
        const disabled = t.disabled;
        const isActive = props.active === t.key;
        return (
          <button
            key={t.key}
            type="button"
            onClick={() => !disabled && props.onChange(t.key)}
            disabled={disabled}
            title={t.matched ? 'Contains rows matching the map search' : undefined}
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
            {t.matched && <span style={{ color: '#ffc400', marginLeft: '0.25rem' }}>●</span>}
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
  const nodeById = useMemo(() => new Map(allNodes.map((n) => [n.id, n])), [allNodes]);

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
          gap: '0.5rem 1.5rem',
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
        <span className={`badge badge-${node.status === 'up' ? 'success' : node.status === 'down' ? 'danger' : node.status === 'alerting' ? 'warning' : 'secondary'}`}>{node.status || 'unknown'}</span>
        {node.group_name && (
          <>
            <span className="text-muted">Group</span>
            <span>{node.group_name}</span>
          </>
        )}
        <span className="text-muted">In Inventory</span>
        <span>{node.in_inventory ? 'Yes' : 'No'}</span>
        {node.meraki && (
          <>
            <span className="text-muted">{providerLabel(node.meraki.provider)}</span>
            <span>
              {node.meraki.site_name || providerScopeName(node.meraki.provider)}
              {node.meraki.serial ? ` · ${node.meraki.serial}` : ''}
            </span>
          </>
        )}
        {node.instance && (
          <>
            <span className="text-muted">AWS instance</span>
            <span>{node.instance.id}</span>
            {node.instance.subnet && (
              <>
                <span className="text-muted">Subnet</span>
                <span>{node.instance.subnet}</span>
              </>
            )}
            {/* For an AWS node the provider row above already names the VPC. */}
            {node.meraki?.provider !== 'aws' && node.instance.vpc && (
              <>
                <span className="text-muted">VPC</span>
                <span>{node.instance.vpc}</span>
              </>
            )}
          </>
        )}
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
              const peer = nodeById.get(peerId);
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

      {!node.in_inventory && node.ip && !['wan', 'vpn_peer', 'cloud', 'users', 'user', 'vpc'].includes(node.meraki?.kind ?? '') && (
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
      {/* Wider than the panel when a table has many columns; scroll, don't squeeze. */}
      <div style={SCROLL_X_STYLE}>
        <table
          className="data-table"
          style={{ fontSize: '0.75rem', width: '100%' }}
        >
          <thead>
            <tr>
              {props.columns.map((c) => (
                <th key={c} style={{ ...DETAIL_CELL_STYLE, textAlign: 'left', whiteSpace: 'nowrap' }}>
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {props.rows.map((cells, i) => (
              <tr key={i}>
                {cells.map((cell, j) => (
                  <td key={j} style={DETAIL_CELL_STYLE}>{cell}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
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
