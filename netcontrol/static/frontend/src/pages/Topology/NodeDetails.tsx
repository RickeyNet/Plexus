import { useMemo, useRef, useState } from 'react';

import { useMerakiNodeDetails } from '@/api/meraki';
import {
  type StpState,
  type TopologyEdge,
  type TopologyMerakiRef,
  type TopologyNode,
  useUpdateHostCategory,
} from '@/api/topology';
import { TabBar } from '@/components/TabBar';
import {
  abbreviateInterface,
  DETAILS_PANEL_MIN_WIDTH,
  DEVICE_ROLES,
  draggedPanelWidth,
  edgeProtocolLabel,
  formatBps,
  MAP_PANEL_MAX_WIDTH,
  nodeKindLabel,
  providerLabel,
  providerScopeName,
  providerSourceName,
  stpPortKey,
  stpTone,
} from './helpers';
import {
  HostAuditTab,
  HostConfigTab,
  HostErrorsTab,
  HostInterfacesTab,
  HostMacArpTab,
  HostVlansTab,
  SubHeading,
} from './HostDataTabs';
import { canAddToInventory } from './inventoryAdd';
import { MerakiDetails } from './MerakiDetails';
import { isOpnsenseDevice } from './opnsenseRules';
import { OpnsenseRulesTab } from './OpnsenseRulesTab';
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
type TabKey = 'overview' | MerakiView | 'aws' | 'config' | 'rules' | 'errors' | 'audit';

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
  // An OPNsense firewall's filter rules, read from its config.xml backup.
  { key: 'rules', label: 'Rules' },
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
    if (t.key === 'rules') return hostId != null && isOpnsenseDevice(node.device_type);
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
  // A map search opens the first tab holding a matching row, once per node
  // and search and once the details have loaded; not in the render that
  // resets the tab for a new node, where `activeTab` is still the old one.
  const autoTabKey = `${node.id}|${searchText ?? ''}`;
  const [autoTabDone, setAutoTabDone] = useState('');
  if (highlightTerms.length && autoTabDone !== autoTabKey && node.id === prevNodeId && (!node.meraki || merakiData)) {
    setAutoTabDone(autoTabKey);
    const firstMatched = tabs.find((t) => t.matched && !t.disabled);
    if (firstMatched && !tabs.some((t) => t.key === activeTab && t.matched)) setActiveTab(firstMatched.key);
  }
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
        // A remembered width never pushes the panel past the map's left edge;
        // a default width also leaves part of a narrow map in view.
        maxWidth: customWidth != null ? 'calc(100% - 1.5rem)' : MAP_PANEL_MAX_WIDTH,
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
            alignItems: 'flex-start',
            gap: '0.5rem',
            marginBottom: '0.5rem',
          }}
        >
          <h4 style={{ margin: 0, minWidth: 0, overflowWrap: 'anywhere' }}>{node.label || 'Unknown'}</h4>
          <button
            type="button"
            className="modal-close"
            aria-label="Close device details"
            onClick={onClose}
            style={{ fontSize: '1.2rem' }}
          >
            ×
          </button>
        </div>

        <TabBar
          size="sm"
          aria-label="Device details sections"
          tabs={tabs.map((t) => ({
            key: t.key,
            disabled: t.disabled,
            title: t.matched ? 'Contains rows matching the map search' : undefined,
            label: (
              <>
                {t.label}
                {t.matched && <span style={{ color: 'var(--warning)', marginLeft: '0.25rem' }}>●</span>}
              </>
            ),
          }))}
          active={shownTab}
          onChange={setActiveTab}
        />

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
            <HostInterfacesTab hostId={hostId} />
          )}
          {shownTab === 'vlans' && hostId != null && <HostVlansTab hostId={hostId} />}
          {shownTab === 'mac' && hostId != null && <HostMacArpTab hostId={hostId} />}
          {shownTab === 'config' && hostId != null && (
            <HostConfigTab hostId={hostId} />
          )}
          {shownTab === 'rules' && hostId != null && <OpnsenseRulesTab hostId={hostId} />}
          {shownTab === 'errors' && hostId != null && (
            <HostErrorsTab hostId={hostId} />
          )}
          {shownTab === 'audit' && hostId != null && <HostAuditTab hostId={hostId} />}
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
            aria-label="Device role"
            className="form-select form-select-sm"
            value={category}
            onChange={(e) => handleCategoryChange(e.target.value)}
            disabled={updateCategory.isPending}
          >
            {DEVICE_ROLES.map((c) => (
              <option key={c} value={c}>{c || '(auto)'}</option>
            ))}
          </select>
        ) : (
          <span>{nodeKindLabel(category) || 'unknown'}</span>
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
        {node.meraki?.ha_peer && (
          <>
            <span className="text-muted">CARP peer</span>
            <span>{node.meraki.ha_peer}</span>
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
              const proto = edgeProtocolLabel(edge, node, peer);
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
                            ? 'rgba(from var(--danger) r g b / 0.2)'
                            : util.utilization_pct > 50
                            ? 'rgba(from var(--warning) r g b / 0.15)'
                            : 'rgba(from var(--success) r g b / 0.15)',
                        color:
                          util.utilization_pct > 75
                            ? 'var(--danger)'
                            : util.utilization_pct > 50
                            ? 'var(--warning)'
                            : 'var(--success)',
                      }}
                    >
                      {util.utilization_pct}% ({formatBps(util.in_bps)} in /{' '}
                      {formatBps(util.out_bps)} out)
                    </div>
                  )}
                  {stp && (
                    <div style={{ marginTop: '0.25rem' }}>
                      <span className={`badge badge-${stpTone(stp.port_state) ?? 'secondary'}`}>
                        STP {stp.port_state ?? 'unknown'}
                        {stp.port_role ? '/' + stp.port_role : ''} VLAN {stp.vlan_id ?? ''}
                      </span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </>
      )}

      {canAddToInventory(node) && (
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
