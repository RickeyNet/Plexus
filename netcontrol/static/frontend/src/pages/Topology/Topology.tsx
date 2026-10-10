import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { DataSet, Network } from 'vis-network/standalone';
import type { Edge as VisEdge, Node as VisNode } from 'vis-network';

import {
  fetchTopologyChanges,
  fetchTopologyStpEvents,
  fetchTopologyStpState,
  openUtilizationStream,
  useDeleteTopologyPositions,
  useDiscoverTopologyStp,
  useInventoryGroupsLite,
  useSaveTopologyPositions,
  useTopology,
  useTopologyOverlayStatus,
  useTopologyPositions,
  type AuditSeverity,
  type ErrorSeverity,
  type StpState,
  type TopologyData,
  type TopologyEdge,
  type TopologyHostStatus,
  type TopologyNode,
  type UtilizationStreamEdge,
} from '@/api/topology';
import { topologyExportUrl, useMerakiSubnets, useTopologyDeepSearch } from '@/api/meraki';
import { PageHelp } from '@/components/PageHelp';
import { AddToInventoryModal } from './AddToInventoryModal';
import { ChangesModal } from './ChangesModal';
import { DiscoveryProgressModal } from './DiscoveryProgressModal';
import { ExportMenu } from './ExportMenu';
import { exportJSON, exportPNG, exportSVG } from './exporters';
import {
  abbreviateInterface,
  edgeProtocolColor,
  filterBySource,
  getTopoThemeColors,
  mapProviders,
  providerLabel,
  isEdgeDown,
  isManagedNode,
  isMerakiEndpointNode,
  isRemoteUserNode,
  merakiNodeKey,
  merakiNodeShape,
  nodeColor,
  nodeIconUrl,
  nodeProvider,
  nodeSearchText,
  nodeShape,
  nodeTitle,
  stpPortKey,
  stpStyle,
  utilColor,
  utilShadow,
  type EdgeColor,
  type SourceFilter,
  type TopoThemeColors,
} from './helpers';
import { crowdedGroups, fitTitles, labelWidth, straighten, tidyLabel, tidyTree, type XY } from './layout';
import { distanceToRoute, routeSourceLinks, traceRoute } from './routes';
import { EdgeDetails } from './EdgeDetails';
import { MAX_PATH_ENDPOINTS, connectPicks, findSubnets, isAddressText, parseTraffic, pathSites, subnetOptionLabel, type PathPick } from './paths';
import { PathTrace } from './PathTracePanel';
import { legKey, mergeHighlights, pathTraceQuery, reverseTraceQuery, uncheckedTraceNote, type TraceHighlight } from './pathTrace';
import { NodeDetails } from './NodeDetails';
import { SourcesModal } from './SourcesModal';
import { StpEventsModal } from './StpEventsModal';
import {
  TopologySearchPanel,
  type HighlightTarget,
} from './TopologySearchPanel';

type LayoutMode = 'tidy' | 'physics' | 'circular' | 'hierarchical-UD' | 'hierarchical-DU' | 'hierarchical-LR' | 'hierarchical-RL';

interface NodeMeta {
  raw: TopologyNode;
  circularX?: number;
  circularY?: number;
}

interface EdgeMeta {
  raw: TopologyEdge;
  roundness: number;
}

interface SearchResult {
  node: TopologyNode;
  /** Where a deep (Meraki detail) match was found, e.g. "VLANs: 20 · Voice". */
  snippet?: string;
}

const DOWN_EDGE_COLOR = { color: '#f44336', highlight: '#ef5350', hover: '#ef5350', opacity: 0.9 };
const MAX_SEARCH_RESULTS = 40;
// Site frame padding: roomy for free-form layouts, snug for the tidy tree,
// whose rows leave just enough space between sites for a frame and its title.
const SITE_FRAME = { padX: 75, padY: 75, font: 26 };
const TIDY_SITE_FRAME = { padX: 60, padY: 34, font: 16 };
// The tidy layout's region of each source (inventory, Meraki, Cato, ...),
// drawn when there is more than one. It fits in the layout's SOURCE_GAP.
const SOURCE_FRAME = { padX: 110, padY: 80, font: 30 };
// Past this size the per-frame canvas work matters more than polish: glows
// are dropped, hover tracking is off and links hide while the view moves.
const LARGE_MAP_NODES = 600;
const LARGE_MAP_EDGES = 1200;
// With more VPN tunnels than this, only the selected device's are drawn
// unless the operator asks for all of them.
const AUTO_HIDE_TUNNELS = 300;
const TUNNEL_PROTOCOLS = new Set(['vpn', 'vpn-ipsec']);

// The links from the Cato Cloud to its PoPs: the Cato backbone, a handful of
// links that are always drawn however many tunnels the map hides.
function catoBackbone(d: TopologyData | undefined): Set<number | string> {
  const ids = new Set<number | string>();
  if (!d) return ids;
  const ref = new Map(d.nodes.map((n) => [n.id, n.meraki?.provider === 'cato' ? n.meraki.node_id : '']));
  for (const e of d.edges) {
    const ends = [ref.get(e.from) ?? '', ref.get(e.to) ?? ''];
    if (ends.includes('cato:cloud') && ends.some((id) => id.startsWith('pop:'))) ids.add(e.id);
  }
  return ids;
}

// `title` is the text written over the box (the tidy layout shortens a name
// that would run into the next box); the full name otherwise.
type SiteBoxes = Map<string, { name: string; title?: string; x0: number; y0: number; x1: number; y1: number }>;

export function Topology() {
  const qc = useQueryClient();
  const [groupFilter, setGroupFilter] = useState<string>('');
  const [layout, setLayout] = useState<LayoutMode>('tidy');
  const [labelsVisible, setLabelsVisible] = useState(false);
  const [utilOverlay, setUtilOverlay] = useState(false);
  const [stpOverlay, setStpOverlay] = useState(false);
  const [stpVlan, setStpVlan] = useState(1);
  const [stpAllVlans, setStpAllVlans] = useState(false);
  const [pathMode, setPathMode] = useState(false);
  const [pathPicks, setPathPicks] = useState<PathPick[]>([]);
  // Traffic the trace of a path is asked about: 'tcp/443', empty for any.
  const [pathTraffic, setPathTraffic] = useState('');
  // Map highlight of each traced leg (by legKey): the request hops shown.
  const [traceHighlights, setTraceHighlights] = useState<Record<string, TraceHighlight | null>>({});
  const [pathSubnetInput, setPathSubnetInput] = useState('');
  const [pathSiteInput, setPathSiteInput] = useState('');
  const [pathNote, setPathNote] = useState('');
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [spacing, setSpacing] = useState(220);
  const [repulsion, setRepulsion] = useState(8000);
  const [edgeLen, setEdgeLen] = useState(280);
  const [search, setSearch] = useState('');
  const [searchResultsVisible, setSearchResultsVisible] = useState(false);
  const [searchHighlightIdx, setSearchHighlightIdx] = useState(-1);
  const [detailsNode, setDetailsNode] = useState<TopologyNode | null>(null);
  const [detailsEdge, setDetailsEdge] = useState<TopologyEdge | null>(null);
  const [addInvTarget, setAddInvTarget] = useState<TopologyNode | null>(null);
  const [discoveryOpen, setDiscoveryOpen] = useState(false);
  const [changesOpen, setChangesOpen] = useState(false);
  const [stpEventsOpen, setStpEventsOpen] = useState(false);
  const [actionMsg, setActionMsg] = useState<string | null>(null);
  const [changeBadge, setChangeBadge] = useState(0);
  const [stpBadge, setStpBadge] = useState(0);
  const [searchPanelOpen, setSearchPanelOpen] = useState(false);
  const [statusOverlay, setStatusOverlay] = useState(false);
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>('all');
  const [sourcesOpen, setSourcesOpen] = useState(false);
  const [debouncedSearch, setDebouncedSearch] = useState('');
  // Search text behind the current highlight / open details pane, so the
  // Meraki tabs can mark the rows that matched.
  const [appliedSearch, setAppliedSearch] = useState('');
  const [highlightCount, setHighlightCount] = useState(0);
  // null = automatic: all VPN tunnels on a small map, on demand on a large one.
  const [tunnelPref, setTunnelPref] = useState<boolean | null>(null);

  const containerRef = useRef<HTMLDivElement | null>(null);
  const networkRef = useRef<Network | null>(null);
  const nodesDSRef = useRef<DataSet<VisNode> | null>(null);
  const edgesDSRef = useRef<DataSet<VisEdge> | null>(null);
  const themeRef = useRef<TopoThemeColors | null>(null);
  const savedPositionsRef = useRef<Record<string, { x: number; y: number }>>({});
  const stpStateRef = useRef<Map<string, StpState>>(new Map());
  const originalColorsRef = useRef<{ nodes: [number | string, unknown][]; edges: [number | string, unknown][] } | null>(null);
  const savePosTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const utilCleanupRef = useRef<(() => void) | null>(null);
  const nodeMetaRef = useRef<Map<number | string, NodeMeta>>(new Map());
  const edgeMetaRef = useRef<Map<number | string, EdgeMeta>>(new Map());
  const flashTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Tidy-tree positions of the rendered graph; null in every other layout.
  const tidyPosRef = useRef<Map<number | string, XY> | null>(null);
  // The piece of its site each node of the tidy layout is framed in.
  const tidyPiecesRef = useRef<Map<number | string, string>>(new Map());
  // Site frames that would enclose other sites' devices (tidy layout: pieces of sites).
  const crowdedSitesRef = useRef<Set<string>>(new Set());
  // Site frames of the tidy layout, kept until a node moves.
  const siteBoxesRef = useRef<SiteBoxes | null>(null);
  // Source regions of the tidy layout, worked out with the site frames.
  const sourceBoxesRef = useRef<SiteBoxes>(new Map());
  // Links of the tidy layout drawn here instead of by vis, which keeps them
  // hidden: those between two sources (routed over the sources instead of
  // across them) and those on a comb (a hub's links to its spokes).
  const routedEdgesRef = useRef<Set<number | string>>(new Set());
  // Of those, the links between two sources.
  const sourceLinksRef = useRef<Set<number | string>>(new Set());
  // The combs as the layout drew them, before any node was dragged.
  const tidyRoutesRef = useRef<Map<number | string, XY[]>>(new Map());
  // The polyline of every routed link, from live positions.
  const routesRef = useRef<Map<number | string, XY[]>>(new Map());
  // Routed links a highlighted path runs over, drawn even if a hidden tunnel.
  const pathRoutesRef = useRef<Set<number | string>>(new Set());
  // The routed link whose details are open, drawn selected.
  const selectedRouteRef = useRef<number | string | null>(null);
  const largeMapRef = useRef(false);
  const tunnelsByNodeRef = useRef<Map<number | string, TopologyEdge[]>>(new Map());
  // The node whose details are open; its VPN tunnels are always drawn.
  const revealedNodeRef = useRef<number | string | null>(null);
  const searchBlurTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Live utilization keyed by edge id, kept off the react-query cache so we
  // don't mutate cached data structures.
  const utilByEdgeRef = useRef<Map<number | string, UtilizationStreamEdge['utilization']>>(new Map());

  useEffect(() => {
    return () => {
      if (flashTimerRef.current) clearTimeout(flashTimerRef.current);
      if (searchBlurTimerRef.current) clearTimeout(searchBlurTimerRef.current);
    };
  }, []);

  const groupId = groupFilter ? parseInt(groupFilter, 10) : null;
  const topologyQuery = useTopology(groupId);
  const positionsQuery = useTopologyPositions();
  const groupsQuery = useInventoryGroupsLite();
  const savePositions = useSaveTopologyPositions();
  const deletePositions = useDeleteTopologyPositions();
  const stpScan = useDiscoverTopologyStp();
  const overlayStatusQuery = useTopologyOverlayStatus(statusOverlay);

  const rawData = topologyQuery.data;
  const hasMeraki = !!rawData?.nodes.some((n) => n.meraki);
  const providersOnMap = useMemo(() => mapProviders(rawData), [rawData]);
  // A provider that is no longer on the map (its source was deleted) shows everything again.
  const activeFilter: SourceFilter =
    sourceFilter.startsWith('provider:') && !providersOnMap.includes(sourceFilter.slice('provider:'.length))
      ? 'all'
      : sourceFilter;
  const data = useMemo(() => filterBySource(rawData, activeFilter), [rawData, activeFilter]);
  const backbone = useMemo(() => catoBackbone(data), [data]);
  const backboneRef = useRef(backbone);
  backboneRef.current = backbone;
  const tunnelCount = useMemo(
    () => data?.edges.filter((e) => TUNNEL_PROTOCOLS.has(e.protocol ?? '') && !backbone.has(e.id)).length ?? 0,
    [data, backbone],
  );
  const showAllTunnels = tunnelPref ?? tunnelCount <= AUTO_HIDE_TUNNELS;
  const showAllTunnelsRef = useRef(showAllTunnels);
  showAllTunnelsRef.current = showAllTunnels;
  const positions = positionsQuery.data;
  const deepSearch = useTopologyDeepSearch(hasMeraki ? debouncedSearch : '');

  // Debounce the deep (server-side) search so typing doesn't fire a request
  // per keystroke; the local name/IP match stays instant.
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(search), 250);
    return () => clearTimeout(timer);
  }, [search]);
  const statusByHostRef = useRef<Map<number, TopologyHostStatus>>(new Map());

  // Hook up theme colors once on mount.
  useEffect(() => {
    themeRef.current = getTopoThemeColors();
  }, []);

  // Sync saved positions from server.
  useEffect(() => {
    if (positions) savedPositionsRef.current = { ...positions };
  }, [positions]);

  // Sync change badge from topology fetch.
  const [prevUnackChanges, setPrevUnackChanges] = useState(data?.unacknowledged_changes);
  if (data?.unacknowledged_changes !== prevUnackChanges) {
    setPrevUnackChanges(data?.unacknowledged_changes);
    if (data?.unacknowledged_changes != null) setChangeBadge(data.unacknowledged_changes);
  }

  // Initial STP event badge fetch.
  useEffect(() => {
    fetchTopologyStpEvents(true, 1)
      .then((r) => setStpBadge(r.unacknowledged_count ?? 0))
      .catch(() => {});
  }, []);

  // Build / rebuild network when data + positions ready, or layout changes.
  useEffect(() => {
    if (!data || !positions || !containerRef.current) return;
    if (!data.nodes.length) {
      destroyNetwork();
      return;
    }
    renderGraph(data, positions, layout);
    return () => {
      // do not destroy here - destroy only on unmount
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, positions, layout]);

  // Cleanup on unmount.
  useEffect(() => {
    return () => {
      if (utilCleanupRef.current) utilCleanupRef.current();
      if (savePosTimerRef.current) clearTimeout(savePosTimerRef.current);
      destroyNetwork();
    };
  }, []);

  // Util overlay stream.
  useEffect(() => {
    if (utilOverlay) {
      utilCleanupRef.current = openUtilizationStream(30, applyUtilizationUpdate);
    } else if (utilCleanupRef.current) {
      utilCleanupRef.current();
      utilCleanupRef.current = null;
    }
    refreshEdgeStyles();
    refreshNodeStyles();
    return () => {
      // cleanup handled by next toggle / unmount
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [utilOverlay]);

  // STP overlay loading.
  useEffect(() => {
    if (!stpOverlay) {
      stpStateRef.current = new Map();
      refreshEdgeStyles();
      return;
    }
    let cancelled = false;
    fetchTopologyStpState(groupFilter || null, null, stpAllVlans ? 1 : stpVlan, 20000)
      .then((r) => {
        if (cancelled) return;
        const map = new Map<string, StpState>();
        for (const row of r.states ?? []) {
          map.set(stpPortKey(row.host_id, row.interface_name ?? ''), row);
        }
        stpStateRef.current = map;
        setStpBadge(r.unacknowledged_events ?? 0);
        refreshEdgeStyles();
        if ((r.count ?? 0) === 0) {
          flash('No STP data yet. Click "Scan STP" to poll devices.');
        }
      })
      .catch((e: Error) => {
        if (cancelled) return;
        setStpOverlay(false);
        stpStateRef.current = new Map();
        flash(`Failed to load STP overlay: ${e.message}`);
      });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stpOverlay, stpVlan, stpAllVlans, groupFilter]);

  useEffect(() => {
    syncTunnelVisibility();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showAllTunnels]);

  // Opening a device's details draws its VPN tunnels; closing hides them again.
  useEffect(() => {
    const prev = revealedNodeRef.current;
    const next = detailsNode?.id ?? null;
    if (prev === next) return;
    revealedNodeRef.current = next;
    syncTunnelVisibility([prev, next].filter((id) => id != null));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [detailsNode]);

  // The routed link whose details are open is drawn selected.
  useEffect(() => {
    const id = detailsEdge && routedEdgesRef.current.has(detailsEdge.id) ? detailsEdge.id : null;
    if (selectedRouteRef.current === id) return;
    selectedRouteRef.current = id;
    networkRef.current?.redraw();
  }, [detailsEdge]);

  // Refresh edge labels in-place when toggled.
  useEffect(() => {
    refreshEdgeStyles();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [labelsVisible]);

  // Status overlay: rebuild the per-host map and restyle when toggle flips
  // or fresh data arrives. The map keys on host_id (number), but topology
  // node ids include external neighbors with string ids -- those have no
  // status data and are skipped during apply.
  useEffect(() => {
    if (!statusOverlay) {
      statusByHostRef.current = new Map();
      refreshNodeStyles();
      refreshEdgeStyles();
      return;
    }
    const next = new Map<number, TopologyHostStatus>();
    for (const h of overlayStatusQuery.data?.hosts ?? []) next.set(h.host_id, h);
    statusByHostRef.current = next;
    refreshNodeStyles();
    refreshEdgeStyles();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [statusOverlay, overlayStatusQuery.data]);

  // Apply settings tweaks live.
  useEffect(() => {
    const network = networkRef.current;
    if (!network) return;
    if (layout.startsWith('hierarchical-')) {
      network.setOptions({
        layout: {
          hierarchical: { nodeSpacing: spacing, levelSeparation: Math.round(edgeLen * 0.78) },
        },
      });
    } else if (layout === 'physics') {
      network.setOptions({
        physics: {
          enabled: true,
          barnesHut: {
            gravitationalConstant: -repulsion,
            springLength: edgeLen,
            avoidOverlap: 0.3,
          },
        },
      });
      network.stabilize(200);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [spacing, repulsion, edgeLen]);

  function destroyNetwork() {
    if (networkRef.current) {
      networkRef.current.destroy();
      networkRef.current = null;
    }
    nodesDSRef.current = null;
    edgesDSRef.current = null;
  }

  function flash(msg: string) {
    setActionMsg(msg);
    if (flashTimerRef.current) clearTimeout(flashTimerRef.current);
    flashTimerRef.current = setTimeout(() => {
      flashTimerRef.current = null;
      setActionMsg(null);
    }, 4000);
  }

  function buildNodeMeta(d: typeof data): Map<number | string, NodeMeta> {
    const m = new Map<number | string, NodeMeta>();
    if (!d) return m;
    for (const n of d.nodes) m.set(n.id, { raw: n });
    return m;
  }

  function assignParallelEdgeRoundness(edges: TopologyEdge[]): Map<number | string, EdgeMeta> {
    const meta = new Map<number | string, EdgeMeta>();
    const pairMap: Record<string, TopologyEdge[]> = {};
    for (const e of edges) {
      const a = String(e.from) < String(e.to) ? e.from : e.to;
      const b = a === e.from ? e.to : e.from;
      const key = `${a}||${b}`;
      if (!pairMap[key]) pairMap[key] = [];
      pairMap[key].push(e);
    }
    for (const group of Object.values(pairMap)) {
      if (group.length <= 1) {
        meta.set(group[0].id, { raw: group[0], roundness: 0.4 });
      } else {
        const step = 0.5 / group.length;
        group.forEach((e, i) => {
          meta.set(e.id, { raw: e, roundness: 0.15 + step * i });
        });
      }
    }
    return meta;
  }

  // The soft glow behind nodes and links. Canvas shadows are by far the
  // most expensive thing drawn, so a large map goes without.
  function glow(color: string, size: number) {
    return largeMapRef.current ? { enabled: false } : { enabled: true, color, size, x: 0, y: 0 };
  }

  // The tunnels the VPN Tunnels button hides and shows: all but the Cato backbone.
  function optionalTunnel(e: TopologyEdge): boolean {
    return TUNNEL_PROTOCOLS.has(e.protocol ?? '') && !backboneRef.current.has(e.id);
  }

  // Whether vis draws the link: not a routed one, nor a tunnel that is hidden.
  function visHidden(e: TopologyEdge): boolean {
    return routedEdgesRef.current.has(e.id) || tunnelHidden(e);
  }

  function tunnelHidden(e: TopologyEdge): boolean {
    if (showAllTunnelsRef.current || !optionalTunnel(e)) return false;
    const revealed = revealedNodeRef.current;
    return revealed == null || (e.from !== revealed && e.to !== revealed);
  }

  // Re-apply which VPN tunnels are drawn: all of them, or just those of the
  // given nodes when only a selection changed.
  function syncTunnelVisibility(nodeIds?: (number | string)[]) {
    const edgesDS = edgesDSRef.current;
    if (!edgesDS) return;
    const lists = nodeIds
      ? nodeIds.map((id) => tunnelsByNodeRef.current.get(id) ?? [])
      : [...tunnelsByNodeRef.current.values()];
    const updates = new Map<number | string, { id: number | string; hidden: boolean }>();
    for (const list of lists) {
      for (const e of list) updates.set(e.id, { id: e.id, hidden: visHidden(e) });
    }
    if (updates.size) edgesDS.update([...updates.values()] as never);
    // The routed links are drawn by drawMerakiSites, whatever vis redraws.
    networkRef.current?.redraw();
  }

  function buildVisNode(n: TopologyNode, savedPos: Record<string, { x: number; y: number }>, circularXY?: { x: number; y: number }): VisNode {
    const tc = themeRef.current ?? getTopoThemeColors();
    const overlay = nodeOverlayProps(n, tc);
    const iconUrl = nodeIconUrl(n);
    const tidyXY = tidyPosRef.current?.get(n.id);
    const node: VisNode = {
      id: n.id as never,
      label: tidyPosRef.current ? tidyLabel(n.label) : n.label,
      title: nodeTitle(n),
      shape: iconUrl ? 'circularImage' : n.source === 'meraki' ? merakiNodeShape(n) : nodeShape(n.device_type),
      image: iconUrl,
      color: overlay.color,
      size: isMerakiEndpointNode(n) ? 11 : isRemoteUserNode(n) ? 14 : isManagedNode(n) ? 25 : 18,
      borderWidth: overlay.borderWidth,
      borderWidthSelected: 4,
      shapeProperties: { borderDashes: isManagedNode(n) ? false : [5, 5] },
      shadow: glow(overlay.shadowColor, overlay.shadowSize),
      font: {
        color: tc.nodeFont,
        size: 12,
        face: 'Inter, sans-serif',
        strokeWidth: 3,
        strokeColor: tc.nodeFontStroke,
      },
    };
    const key = String(n.id);
    if (savedPos[key]) {
      (node as Record<string, unknown>).x = savedPos[key].x;
      (node as Record<string, unknown>).y = savedPos[key].y;
      (node as Record<string, unknown>).fixed = { x: true, y: true };
      (node as Record<string, unknown>).physics = false;
    } else if (tidyXY) {
      (node as Record<string, unknown>).x = tidyXY.x;
      (node as Record<string, unknown>).y = tidyXY.y;
      (node as Record<string, unknown>).physics = false;
    } else if (n.x != null && n.y != null) {
      // Meraki sites arrive pre-arranged; keeping them out of the physics
      // simulation is what lets a large organization open instantly. They
      // stay draggable, and a drag pins them like any other node.
      (node as Record<string, unknown>).x = n.x;
      (node as Record<string, unknown>).y = n.y;
      (node as Record<string, unknown>).physics = false;
    } else if (circularXY) {
      (node as Record<string, unknown>).x = circularXY.x;
      (node as Record<string, unknown>).y = circularXY.y;
    }
    return node;
  }

  function nodeOverlayProps(n: TopologyNode, tc: TopoThemeColors) {
    const baseColor = nodeColor(n, tc);
    const merakiProblem = n.source === 'meraki' && ['offline', 'alerting'].includes(n.meraki?.status ?? '');
    const baseBorder = merakiProblem ? 4 : isManagedNode(n) ? 2.5 : 1.5;
    const pctRaw = n.ipam_utilization_pct;
    const hasIpamUtil = utilOverlay && pctRaw != null && !Number.isNaN(Number(pctRaw));

    // Util overlay wins over status overlay because util is a live metric
    // and the borders/shadows already encode the same dimension.
    if (hasIpamUtil) {
      const pct = Math.max(0, Math.min(100, Number(pctRaw)));
      const utilHex = utilColor(pct).color;
      return {
        color: {
          ...baseColor,
          border: utilHex,
          highlight: { ...baseColor.highlight, border: utilHex },
          hover: { ...baseColor.hover, border: utilHex },
        },
        borderWidth: n.in_inventory ? 5 : 3,
        shadowColor: utilShadow(pct),
        shadowSize: n.in_inventory ? 22 : 12,
      };
    }

    if (statusOverlay && typeof n.id === 'number') {
      const status = statusByHostRef.current.get(n.id);
      const badge = statusBadge(status);
      if (badge) {
        return {
          color: {
            ...baseColor,
            border: badge.color,
            highlight: { ...baseColor.highlight, border: badge.color },
            hover: { ...baseColor.hover, border: badge.color },
          },
          borderWidth: n.in_inventory ? 5 : 3,
          shadowColor: badge.shadow,
          shadowSize: n.in_inventory ? 22 : 12,
        };
      }
    }

    return {
      color: baseColor,
      borderWidth: baseBorder,
      shadowColor: baseColor.border,
      shadowSize: isManagedNode(n) ? 18 : 8,
    };
  }

  // Pick a single worst-severity color for a host. critical/high/audit-critical
  // dominate; medium and warning give a softer amber; low/info still light up
  // so operators can see the device "has something" without it screaming.
  function statusBadge(s: TopologyHostStatus | undefined) {
    if (!s) return null;
    const audit: AuditSeverity | null = s.audit_worst;
    const err: ErrorSeverity | null = s.errors_worst;
    const hasDrift = s.drift_open > 0;
    if (audit === 'critical' || err === 'critical') {
      return { color: '#f44336', shadow: 'rgba(244,67,54,0.5)', tier: 'critical' as const };
    }
    if (audit === 'high' || err === 'high') {
      return { color: '#ff7043', shadow: 'rgba(255,112,67,0.45)', tier: 'high' as const };
    }
    if (audit === 'medium' || err === 'warning' || hasDrift) {
      return { color: '#ffc107', shadow: 'rgba(255,193,7,0.4)', tier: 'medium' as const };
    }
    if (audit === 'low' || audit === 'info' || err === 'info') {
      return { color: '#29b6f6', shadow: 'rgba(41,182,246,0.35)', tier: 'low' as const };
    }
    return null;
  }

  // Worst-of-endpoints status color for an edge -- so a link to/from a
  // device with active errors lights up too.
  function edgeStatusColor(e: TopologyEdge): string | null {
    if (!statusOverlay) return null;
    const fromId = typeof e.from === 'number' ? e.from : null;
    const toId = typeof e.to === 'number' ? e.to : null;
    const fromBadge = fromId != null ? statusBadge(statusByHostRef.current.get(fromId)) : null;
    const toBadge = toId != null ? statusBadge(statusByHostRef.current.get(toId)) : null;
    const rank = { critical: 0, high: 1, medium: 2, low: 3 } as const;
    const candidates = [fromBadge, toBadge].filter(Boolean) as NonNullable<typeof fromBadge>[];
    if (!candidates.length) return null;
    candidates.sort((a, b) => rank[a.tier] - rank[b.tier]);
    return candidates[0].color;
  }

  function edgeOverlayProps(edge: TopologyEdge) {
    const tc = themeRef.current ?? getTopoThemeColors();
    const util = utilByEdgeRef.current.get(edge.id) ?? edge.utilization;
    const hasUtil = utilOverlay && util && util.utilization_pct != null;
    const utilPct = hasUtil && util ? util.utilization_pct : 0;
    const utilWidth = hasUtil && util ? (util.width ?? (2 + (utilPct / 100) * 6)) : 2;
    const utilColorOverride = hasUtil && util ? (util.color ?? utilColor(utilPct)) : null;
    const stp = stpOverlay && edge.from_host_id && edge.source_interface
      ? stpStateRef.current.get(stpPortKey(edge.from_host_id, edge.source_interface))
      : null;
    const stpStl = stp ? stpStyle(stp.port_state) : null;
    const srcIface = abbreviateInterface(edge.source_interface);
    const tgtIface = abbreviateInterface(edge.target_interface);
    let label = [srcIface, tgtIface].filter(Boolean).join(' → ') || '';
    if (hasUtil) label = `${label ? label + ' ' : ''}(${utilPct}%)`;
    if (stpStl && stp) {
      const role = stp.port_role ? `/${stp.port_role}` : '';
      label = `${label ? label + ' ' : ''}[STP:${stp.port_state}${role}]`;
    }
    const protoShadow: Record<string, string> = {
      lldp: 'rgba(0,230,118,0.3)',
      ospf: 'rgba(255,171,64,0.3)',
      bgp: 'rgba(224,64,251,0.3)',
      'inferred-fdb': 'rgba(158,158,158,0.25)',
    };
    const baseProtocolShadow = protoShadow[edge.protocol ?? ''] ?? 'rgba(0,176,255,0.3)';
    const protoDash: false | number[] = stpStl ? stpStl.dashes
      : edge.protocol === 'lldp' ? [8, 5]
      : edge.protocol === 'ospf' ? [12, 4, 4, 4]
      : edge.protocol === 'bgp' ? [4, 4]
      : edge.protocol === 'inferred-fdb' ? [2, 4]
      : edge.protocol === 'vpn' ? [10, 6]
      : edge.protocol === 'vpn-ipsec' ? [3, 5]
      : edge.protocol === 'wan' ? [4, 4]
      : edge.protocol === 'management' ? [2, 4]
      : false;
    // A Meraki VPN tunnel / WAN uplink the Dashboard reports as down.
    const downColor = isEdgeDown(edge) ? DOWN_EDGE_COLOR : null;
    const baseWidth = edge.protocol === 'stack' ? Math.max(utilWidth, 4) : utilWidth;
    // Status overlay paints the edge with the worst-endpoint badge color
    // *only* when neither STP nor live-util is overriding (those are more
    // semantically loaded and the operator is already getting a heatmap
    // signal on the endpoints).
    const statusHex = !stpStl && !hasUtil ? edgeStatusColor(edge) : null;
    const statusShadow = statusHex ? hexToRgba(statusHex, 0.4) : null;

    return {
      label,
      color: stpStl
        ? stpStl.color
        : (utilColorOverride || (statusHex ? { color: statusHex, highlight: statusHex, hover: statusHex, opacity: 0.9 } : (downColor ?? edgeProtocolColor(edge.protocol, tc)))),
      width: stpStl ? Math.max(utilWidth, stpStl.width) : (statusHex ? Math.max(utilWidth, 3) : baseWidth),
      dashes: protoDash,
      shadowColor: stpStl
        ? stpStl.shadow
        : (hasUtil ? utilShadow(utilPct) : (statusShadow ?? baseProtocolShadow)),
    };
  }

  function hexToRgba(hex: string, alpha: number): string {
    const m = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    if (!m) return hex;
    return `rgba(${parseInt(m[1], 16)},${parseInt(m[2], 16)},${parseInt(m[3], 16)},${alpha})`;
  }

  function buildVisEdge(e: TopologyEdge, roundness: number): VisEdge {
    const tc = themeRef.current ?? getTopoThemeColors();
    const overlay = edgeOverlayProps(e);
    const fullLabel = overlay.label;
    const displayLabel = labelsVisible ? fullLabel : '';
    return {
      id: e.id as never,
      from: e.from as never,
      to: e.to as never,
      label: displayLabel,
      color: overlay.color,
      dashes: overlay.dashes,
      width: overlay.width,
      hoverWidth: 0.5,
      selectionWidth: 1,
      hidden: visHidden(e),
      shadow: glow(overlay.shadowColor, 6),
      font: { size: 9, color: tc.edgeFont, strokeWidth: 2, strokeColor: tc.edgeFontStroke, align: 'middle' },
      smooth: edgeSmooth(e, roundness),
      title: fullLabel || undefined,
    } as VisEdge;
  }

  // Tidy tree: links leave nodes downward and enter from above, like
  // branches. A link between two nodes of the same row bows out instead, so
  // it does not run straight through the nodes side by side between them.
  function edgeSmooth(e: TopologyEdge, roundness: number) {
    const tidy = tidyPosRef.current;
    if (!tidy) return { enabled: true, type: 'continuous', roundness };
    const a = tidy.get(e.from);
    const b = tidy.get(e.to);
    if (a && b && a.y === b.y) return { enabled: true, type: 'curvedCW', roundness: 0.1 + roundness / 2 };
    return { enabled: true, type: 'cubicBezier', forceDirection: 'vertical', roundness: 0.3 + roundness / 2 };
  }

  function siteFrame() {
    return tidyPosRef.current ? TIDY_SITE_FRAME : SITE_FRAME;
  }

  // The frame a site member is drawn in: its site, or in the tidy layout the
  // piece of its site the tree placed it in.
  function frameKey(id: number | string, orgRef: number, siteId: string): string {
    return (tidyPosRef.current && tidyPiecesRef.current.get(id)) || merakiNodeKey(orgRef, siteId);
  }

  // Which Meraki site frames to leave out because they would swallow other
  // sites' devices. Only the tidy layout has positions stable enough to tell.
  function refreshCrowdedSites() {
    const network = networkRef.current;
    siteBoxesRef.current = null;
    if (!network || !tidyPosRef.current) {
      crowdedSitesRef.current = new Set();
      return;
    }
    const live = network.getPositions();
    const placed: { group: string; x: number; y: number }[] = [];
    for (const meta of nodeMetaRef.current.values()) {
      const pos = live[meta.raw.id as never];
      if (!pos) continue;
      const ref = meta.raw.meraki;
      placed.push({ group: ref?.site_id ? frameKey(meta.raw.id, ref.org_ref, ref.site_id) : '', x: pos.x, y: pos.y });
    }
    const frame = siteFrame();
    crowdedSitesRef.current = crowdedGroups(placed, frame.padX, frame.padY);
  }

  function renderGraph(d: typeof data, savedPos: Record<string, { x: number; y: number }>, mode: LayoutMode) {
    if (!d || !containerRef.current) return;
    themeRef.current = getTopoThemeColors();
    const isTidy = mode === 'tidy';
    const large = d.nodes.length > LARGE_MAP_NODES || d.edges.length > LARGE_MAP_EDGES;
    largeMapRef.current = large;
    const tidy = isTidy ? tidyTree(d.nodes, d.edges) : null;
    tidyPosRef.current = tidy?.positions ?? null;
    tidyPiecesRef.current = tidy?.pieces ?? new Map();
    const sourceLinks = new Set<number | string>();
    if (tidy) {
      const sourceOf = new Map(d.nodes.map((n) => [n.id, nodeProvider(n)]));
      if (new Set(sourceOf.values()).size > 1) {
        for (const e of d.edges) if (sourceOf.get(e.from) !== sourceOf.get(e.to)) sourceLinks.add(e.id);
      }
    }
    sourceLinksRef.current = sourceLinks;
    tidyRoutesRef.current = tidy?.routes ?? new Map();
    routedEdgesRef.current = new Set([...sourceLinks, ...tidyRoutesRef.current.keys()]);
    routesRef.current = new Map();

    const tunnels = new Map<number | string, TopologyEdge[]>();
    for (const e of d.edges) {
      if (!optionalTunnel(e)) continue;
      for (const end of [e.from, e.to]) {
        const list = tunnels.get(end);
        if (list) list.push(e);
        else tunnels.set(end, [e]);
      }
    }
    tunnelsByNodeRef.current = tunnels;

    nodeMetaRef.current = buildNodeMeta(d);
    edgeMetaRef.current = assignParallelEdgeRoundness(d.edges);

    const isHier = mode.startsWith('hierarchical-');
    const isCircular = mode === 'circular';
    const allPinned =
      d.nodes.length > 0 && d.nodes.every((n) => savedPos[String(n.id)] || (n.x != null && n.y != null));
    const usePhysics = mode === 'physics' && !allPinned;

    const circularXYMap = new Map<number | string, { x: number; y: number }>();
    if (isCircular) {
      const radius = Math.max(200, d.nodes.length * 35);
      d.nodes.forEach((n, i) => {
        if (!savedPos[String(n.id)]) {
          const angle = (2 * Math.PI * i) / d.nodes.length - Math.PI / 2;
          circularXYMap.set(n.id, {
            x: Math.round(radius * Math.cos(angle)),
            y: Math.round(radius * Math.sin(angle)),
          });
        }
      });
    }

    const nodes = new DataSet<VisNode>(d.nodes.map((n) => buildVisNode(n, savedPos, circularXYMap.get(n.id))));
    const edges = new DataSet<VisEdge>(d.edges.map((e) => {
      const meta = edgeMetaRef.current.get(e.id);
      return buildVisEdge(e, meta?.roundness ?? 0.4);
    }));

    let layoutConfig: Record<string, unknown> = {};
    if (isHier) {
      const direction = mode.split('-')[1];
      layoutConfig = {
        hierarchical: { direction, sortMethod: 'hubsize', nodeSpacing: spacing, levelSeparation: 180 },
      };
    }

    const options = {
      nodes: { brokenImage: '/static/img/topo/unknown.svg' },
      physics: {
        enabled: isCircular || isTidy ? false : usePhysics,
        barnesHut: {
          gravitationalConstant: -repulsion,
          centralGravity: 0.15,
          springLength: edgeLen,
          springConstant: 0.025,
          damping: 0.12,
          avoidOverlap: 0.5,
        },
        stabilization: { iterations: 300, updateInterval: 20 },
      },
      interaction: {
        // Links stay drawn while panning and zooming, even on a large map:
        // without the glow they are cheap, and a map that blinks its links
        // out on every scroll is harder to follow than one a little slower.
        hover: !large,
        tooltipDelay: 150,
        navigationButtons: false,
        keyboard: { enabled: true },
        zoomSpeed: 0.6,
      },
      layout: { improvedLayout: !large, ...layoutConfig },
      edges: { smooth: { enabled: true, type: 'continuous', roundness: 0.4 } },
    };

    if (networkRef.current) networkRef.current.destroy();
    networkRef.current = new Network(containerRef.current, { nodes, edges }, options);
    nodesDSRef.current = nodes;
    edgesDSRef.current = edges;

    networkRef.current.on('click', (params) => {
      if (pathModeRef.current) {
        if (params.nodes.length > 0) togglePathPick(nodePick(params.nodes[0]));
        return;
      }
      if (params.nodes.length > 0) {
        const meta = nodeMetaRef.current.get(params.nodes[0]);
        if (meta) setDetailsNode(meta.raw);
        setDetailsEdge(null);
      } else if (params.edges.length > 0) {
        // Edge-only click: open the edge details panel.
        const edgeId = params.edges[0];
        const meta = edgeMetaRef.current.get(edgeId);
        if (meta) setDetailsEdge(meta.raw);
        setDetailsNode(null);
      } else {
        // vis does not know the routed links (between sources, on a comb).
        const routed = routeAt(params.pointer.canvas);
        const meta = routed != null ? edgeMetaRef.current.get(routed) : undefined;
        setDetailsNode(null);
        setDetailsEdge(meta ? meta.raw : null);
      }
    });

    refreshCrowdedSites();
    networkRef.current.on('beforeDrawing', drawMerakiSites);
    networkRef.current.on('dragging', (params) => {
      // A node is being moved: its site frame has to follow.
      if (params.nodes.length) siteBoxesRef.current = null;
    });

    networkRef.current.on('dragEnd', (params) => {
      if (!params.nodes.length) return;
      const network = networkRef.current!;
      const positionsAfter = network.getPositions(params.nodes);
      const updates: Record<string, { x: number; y: number }> = {};
      for (const nid of params.nodes) {
        const pos = positionsAfter[nid];
        if (!pos) continue;
        const key = String(nid);
        updates[key] = { x: Math.round(pos.x), y: Math.round(pos.y) };
        savedPositionsRef.current[key] = updates[key];
        nodes.update({ id: nid, fixed: { x: true, y: true }, physics: false } as never);
      }
      schedulePositionSave(updates);
      refreshCrowdedSites();
    });

    networkRef.current.on('oncontext', (params) => {
      params.event.preventDefault();
      if (!params.nodes || !params.nodes.length) return;
      const nid = params.nodes[0];
      const key = String(nid);
      if (savedPositionsRef.current[key]) {
        delete savedPositionsRef.current[key];
        const home = tidyPosRef.current?.get(nid);
        if (home) {
          // Tidy layout: an unpinned node goes back to its place in the tree.
          nodes.update({ id: nid, x: home.x, y: home.y, fixed: false, physics: false } as never);
          refreshCrowdedSites();
        } else {
          nodes.update({ id: nid, fixed: false, physics: true } as never);
        }
        savePositions.mutate({ [key]: null });
        flash('Node unpinned');
      }
    });

    if (isHier) {
      networkRef.current.once('stabilizationIterationsDone', () => {
        const network = networkRef.current!;
        const computedPos = network.getPositions();
        const nodeUpdates: VisNode[] = [];
        for (const [nid, pos] of Object.entries(computedPos)) {
          if (!savedPositionsRef.current[String(nid)]) {
            const idVal = /^\d+$/.test(nid) ? Number(nid) : nid;
            nodeUpdates.push({ id: idVal as never, x: pos.x, y: pos.y } as VisNode);
          }
        }
        if (nodeUpdates.length) nodes.update(nodeUpdates);
        network.setOptions({ layout: { hierarchical: { enabled: false } }, physics: { enabled: false } });
        network.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
      });
    } else if (usePhysics) {
      networkRef.current.once('stabilizationIterationsDone', () => {
        networkRef.current!.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
      });
    } else if (allPinned || isCircular || isTidy) {
      setTimeout(() => {
        networkRef.current?.fit({ animation: { duration: 300, easingFunction: 'easeInOutQuad' } });
      }, 50);
    }
  }

  // Frame each Meraki site (network) with a labelled box behind its devices.
  // Boxes are derived from live node positions, so they follow drags.
  function drawMerakiSites(ctx: CanvasRenderingContext2D) {
    const network = networkRef.current;
    if (!network) return;
    const tc = themeRef.current ?? getTopoThemeColors();
    // This runs on every frame. In the tidy layout nodes only move when
    // dragged, so the boxes are worked out once and reused.
    let boxes = tidyPosRef.current ? siteBoxesRef.current : null;
    if (!boxes) {
      boxes = new Map();
      const members = new Map<string, (number | string)[]>();
      const sources: SiteBoxes = new Map();
      const positions = network.getPositions();
      for (const meta of nodeMetaRef.current.values()) {
        const ref = meta.raw.meraki;
        const pos = positions[meta.raw.id as never];
        // A source's frame is where the layout put its nodes: one dragged
        // (and pinned) elsewhere, maybe under an earlier layout, neither
        // stretches it over other sources nor, when it is the last node of
        // a small source, empties it (which would lose the routed links).
        const laid = tidyPosRef.current?.get(meta.raw.id);
        if (laid) {
          const key = nodeProvider(meta.raw);
          const region = sources.get(key);
          if (!region) {
            const name = key ? providerLabel(key) : 'Inventory';
            sources.set(key, { name, x0: laid.x, y0: laid.y, x1: laid.x, y1: laid.y });
          } else {
            region.x0 = Math.min(region.x0, laid.x);
            region.y0 = Math.min(region.y0, laid.y);
            region.x1 = Math.max(region.x1, laid.x);
            region.y1 = Math.max(region.y1, laid.y);
          }
        }
        if (!ref || !ref.site_id || !pos) continue;
        const key = frameKey(meta.raw.id, ref.org_ref, ref.site_id);
        if (crowdedSitesRef.current.has(key)) continue;
        const box = boxes.get(key);
        if (!box) {
          boxes.set(key, { name: ref.site_name, x0: pos.x, y0: pos.y, x1: pos.x, y1: pos.y });
          members.set(key, [meta.raw.id]);
        } else {
          members.get(key)!.push(meta.raw.id);
          box.x0 = Math.min(box.x0, pos.x);
          box.y0 = Math.min(box.y0, pos.y);
          box.x1 = Math.max(box.x1, pos.x);
          box.y1 = Math.max(box.y1, pos.y);
        }
      }
      siteBoxesRef.current = boxes;
      sourceBoxesRef.current = sources.size > 1 ? sources : new Map();
      const site = siteFrame();
      if (tidyPosRef.current) {
        // A long name over a narrow box (a VPC of one node) would be
        // written over the titles of the boxes beside it: it is shortened
        // where it would reach the next box. The tooltip and panel keep it whole.
        const list = [...boxes.values()];
        const titles = fitTitles(
          list.map((b) => ({
            x0: b.x0 - site.padX,
            y0: b.y0 - site.padY,
            x1: b.x1 + site.padX,
            y1: b.y1 + site.padY,
            name: b.name,
          })),
          site.font,
          4,
        );
        list.forEach((b, idx) => {
          b.title = titles[idx];
        });
      }
      // The combs, from where their ends are now: a dragged node keeps its
      // link, joined by a straight stretch to wherever it was dropped.
      const routes = new Map<number | string, XY[]>();
      for (const [id, points] of tidyRoutesRef.current) {
        const raw = edgeMetaRef.current.get(id)?.raw;
        const from = raw ? positions[raw.from as never] : undefined;
        const to = raw ? positions[raw.to as never] : undefined;
        if (!raw || !from || !to) continue;
        // A comb runs down from the hub, which may be either end of the link.
        const laid = tidyPosRef.current?.get(raw.from);
        const fromFirst = !!laid && laid.x === points[0].x && laid.y === points[0].y;
        const [head, tail] = fromFirst ? [from, to] : [to, from];
        routes.set(id, straighten([{ x: head.x, y: head.y }, ...points.slice(1, -1), { x: tail.x, y: tail.y }]));
      }
      if (sources.size > 1 && sourceLinksRef.current.size) {
        const at = new Map<number | string, XY>();
        const labels = new Map<number | string, number>();
        for (const [id, meta] of nodeMetaRef.current) {
          const pos = positions[id as never];
          if (pos) at.set(id, pos);
          labels.set(id, labelWidth(meta.raw.label));
        }
        const links = [...sourceLinksRef.current].flatMap((id) => {
          const raw = edgeMetaRef.current.get(id)?.raw;
          return raw ? [{ id, from: raw.from, to: raw.to }] : [];
        });
        const top = Math.min(...[...sources.values()].map((r) => r.y0)) - SOURCE_FRAME.padY;
        // The site boxes as drawn, titles included, for the routes to keep out of.
        const title = site.font + (site.font > 20 ? 8 : 4);
        const siteRects = [...boxes].map(([key, b]) => {
          const x0 = b.x0 - site.padX;
          const y0 = b.y0 - site.padY;
          return {
            x0,
            x1: b.x1 + site.padX,
            y0: y0 - title,
            y1: b.y1 + site.padY,
            ids: members.get(key) ?? [],
            // About 0.6 em a character, from where the title is written.
            title: { x0, y0: y0 - title, x1: x0 + 4 + (b.title ?? b.name).length * site.font * 0.6, y1: y0 },
          };
        });
        for (const [id, points] of routeSourceLinks(links, at, top, siteRects, labels)) routes.set(id, points);
      }
      routesRef.current = routes;
    }
    const scale = network.getScale();
    ctx.save();
    // Source regions, behind the sites.
    ctx.lineWidth = 3;
    ctx.textAlign = 'left';
    ctx.textBaseline = 'bottom';
    ctx.font = `700 ${SOURCE_FRAME.font}px Inter, sans-serif`;
    for (const region of sourceBoxesRef.current.values()) {
      const x = region.x0 - SOURCE_FRAME.padX;
      const y = region.y0 - SOURCE_FRAME.padY;
      const w = region.x1 - region.x0 + SOURCE_FRAME.padX * 2;
      const h = region.y1 - region.y0 + SOURCE_FRAME.padY * 2;
      ctx.fillStyle = 'rgba(66,165,245,0.04)';
      ctx.strokeStyle = 'rgba(66,165,245,0.4)';
      ctx.setLineDash([14, 10]);
      ctx.beginPath();
      ctx.rect(x, y, w, h);
      ctx.fill();
      ctx.stroke();
      ctx.setLineDash([]);
      if (SOURCE_FRAME.font * scale < 5) continue;
      ctx.fillStyle = tc.nodeFont;
      ctx.globalAlpha = 0.85;
      ctx.fillText(region.name, x + 6, y - 10);
      ctx.globalAlpha = 1;
    }
    ctx.restore();
    const frame = siteFrame();
    // Zoomed far out the titles are a few unreadable pixels each; skip them.
    const titles = frame.font * scale >= 5;
    ctx.save();
    ctx.lineWidth = 2;
    ctx.textAlign = 'left';
    ctx.textBaseline = 'bottom';
    ctx.font = `600 ${frame.font}px Inter, sans-serif`;
    for (const box of boxes.values()) {
      const x = box.x0 - frame.padX;
      const y = box.y0 - frame.padY;
      const w = box.x1 - box.x0 + frame.padX * 2;
      const h = box.y1 - box.y0 + frame.padY * 2;
      ctx.fillStyle = 'rgba(139,195,74,0.05)';
      ctx.strokeStyle = 'rgba(139,195,74,0.45)';
      ctx.beginPath();
      ctx.rect(x, y, w, h);
      ctx.fill();
      ctx.stroke();
      if (!titles) continue;
      ctx.fillStyle = tc.nodeFont;
      ctx.globalAlpha = 0.75;
      ctx.fillText(box.title ?? box.name, x + 4, y - (frame.font > 20 ? 8 : 4));
      ctx.globalAlpha = 1;
    }
    ctx.restore();
    drawRoutedLinks(ctx);
  }

  // A routed link is drawn when vis would draw it: not a hidden tunnel,
  // unless a highlighted path runs over it.
  function routeShown(id: number | string): boolean {
    const raw = edgeMetaRef.current.get(id)?.raw;
    return !!raw && (!tunnelHidden(raw) || pathRoutesRef.current.has(id));
  }

  // The routed links (between sources, and on a comb), styled like vis
  // styles the link (overlays, dimming and highlighting included), under the nodes.
  function drawRoutedLinks(ctx: CanvasRenderingContext2D) {
    const network = networkRef.current;
    const edgesDS = edgesDSRef.current;
    if (!network || !edgesDS || !routesRef.current.size) return;
    const selectedNodes = new Set(network.getSelectedNodes());
    const scale = network.getScale();
    const tc = themeRef.current ?? getTopoThemeColors();
    ctx.save();
    ctx.lineCap = 'round';
    for (const [id, points] of routesRef.current) {
      if (!routeShown(id)) continue;
      const raw = edgeMetaRef.current.get(id)!.raw;
      const item = edgesDS.get(id as never) as unknown as {
        color?: string | Partial<EdgeColor>;
        width?: number;
        dashes?: boolean | number[];
        opacity?: number;
        label?: string;
      } | null;
      if (!item) continue;
      const selected = selectedRouteRef.current === id || selectedNodes.has(raw.from) || selectedNodes.has(raw.to);
      const color = item.color;
      ctx.strokeStyle =
        typeof color === 'string' ? color : (selected ? color?.highlight : undefined) ?? color?.color ?? '#808080';
      ctx.globalAlpha = item.opacity ?? (typeof color === 'object' ? color.opacity : undefined) ?? 1;
      ctx.lineWidth = Math.max((item.width ?? 1) + (selected ? 1 : 0), 0.3 / scale);
      ctx.setLineDash(Array.isArray(item.dashes) ? item.dashes : item.dashes ? [5, 5] : []);
      ctx.beginPath();
      traceRoute(ctx, points, 24);
      ctx.stroke();
      if (item.label && 9 * scale >= 5) {
        // On the stretch across, the longest part of the route.
        const [a, b] = [points[Math.floor((points.length - 1) / 2)], points[Math.floor((points.length - 1) / 2) + 1]];
        ctx.setLineDash([]);
        ctx.globalAlpha = 1;
        ctx.font = '9px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'bottom';
        ctx.lineWidth = 2;
        ctx.strokeStyle = tc.edgeFontStroke;
        ctx.strokeText(item.label, (a.x + b.x) / 2, a.y - 3);
        ctx.fillStyle = tc.edgeFont;
        ctx.fillText(item.label, (a.x + b.x) / 2, a.y - 3);
      }
    }
    ctx.restore();
  }

  // The routed link drawn at a point of the canvas, if any.
  function routeAt(p: XY): number | string | null {
    const network = networkRef.current;
    if (!network) return null;
    const reach = 8 / network.getScale();
    let best: number | string | null = null;
    let bestDistance = reach;
    for (const [id, points] of routesRef.current) {
      if (!routeShown(id)) continue;
      const distance = distanceToRoute(points, p);
      if (distance <= bestDistance) {
        best = id;
        bestDistance = distance;
      }
    }
    return best;
  }

  // Keep pathMode/picks in refs so the click handler always sees the latest.
  const pathModeRef = useRef(pathMode);
  const pathPicksRef = useRef(pathPicks);
  useEffect(() => { pathModeRef.current = pathMode; }, [pathMode]);
  useEffect(() => { pathPicksRef.current = pathPicks; }, [pathPicks]);

  const pathSiteList = useMemo(() => pathSites(data?.nodes ?? []), [data]);
  const subnetsQuery = useMerakiSubnets(pathMode && pathSiteList.length > 0);
  // Map node of every Meraki snapshot node (a device that is also an
  // inventory host resolves to the host's node). The snapshot nodes collapsed
  // into another node (`also_refs`) resolve to it too, so their subnets can
  // be picked; a node's own reference wins.
  const merakiNodeIds = useMemo(() => {
    const byMerakiKey = new Map<string, number | string>();
    for (const n of data?.nodes ?? []) {
      if (n.meraki) byMerakiKey.set(merakiNodeKey(n.meraki.org_ref, n.meraki.node_id), n.id);
    }
    for (const n of data?.nodes ?? []) {
      for (const ref of n.also_refs ?? []) {
        const key = merakiNodeKey(ref.org_ref, ref.node_id);
        if (!byMerakiKey.has(key)) byMerakiKey.set(key, n.id);
      }
    }
    return byMerakiKey;
  }, [data]);
  const resolveMerakiNode = useCallback(
    (orgRef: number, nodeId: string) => merakiNodeIds.get(merakiNodeKey(orgRef, nodeId)),
    [merakiNodeIds],
  );
  // Subnets whose owning device is on the map, with that device's node id.
  const pathSubnets = useMemo(() => {
    const owners = new Map<string, number | string>();
    const list = (subnetsQuery.data?.subnets ?? []).filter((s) => {
      const node = merakiNodeIds.get(merakiNodeKey(s.org_ref, s.node_id));
      if (node === undefined) return false;
      owners.set(subnetOptionLabel(s), node);
      return true;
    });
    return { list, owners };
  }, [subnetsQuery.data, merakiNodeIds]);
  const pathResult = useMemo(() => connectPicks(pathPicks, data?.edges ?? []), [pathPicks, data]);
  const trafficFilter = useMemo(() => parseTraffic(pathTraffic), [pathTraffic]);
  // Legs between two subnets or addresses, which the server traces hop by hop.
  const pathHasTraceLeg = pathResult.legs.some((leg) => pathTraceQuery(leg.from, leg.to, { protocol: '' }) !== null);
  const setLegHighlight = useCallback((key: string, highlight: TraceHighlight | null) => {
    setTraceHighlights((prev) => ((prev[key] ?? null) === highlight ? prev : { ...prev, [key]: highlight }));
  }, []);
  // A traced leg is drawn over the hops of its trace, the others over the links.
  const pathHighlight = useMemo(
    () => mergeHighlights(pathPicks, pathResult.legs, traceHighlights),
    [pathPicks, pathResult, traceHighlights],
  );
  // Redraw the path whenever the picks or traces change or the map is rebuilt.
  useEffect(() => {
    if (!pathMode) return;
    restoreOriginalColors();
    if (pathPicks.length) highlightPath(pathHighlight.nodeIds, pathHighlight.edgeIds);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pathMode, pathHighlight, positions, layout]);

  // The search panel keeps `onHighlight` in a useEffect dep array, so the
  // callback identity must be stable across parent re-renders. Stash the
  // latest impl in a ref and expose a thin caller with a frozen identity.
  const applySearchHighlightRef = useRef<(t: HighlightTarget | null) => void>(
    () => {},
  );
  applySearchHighlightRef.current = applySearchHighlight;
  const stableApplySearchHighlight = useCallback(
    (t: HighlightTarget | null) => applySearchHighlightRef.current(t),
    [],
  );

  function schedulePositionSave(updates: Record<string, { x: number; y: number } | null>) {
    if (savePosTimerRef.current) clearTimeout(savePosTimerRef.current);
    savePosTimerRef.current = setTimeout(() => {
      savePositions.mutate(updates);
    }, 500);
  }

  function refreshEdgeStyles() {
    const network = networkRef.current;
    const edgesDS = edgesDSRef.current;
    if (!network || !edgesDS || !data) return;
    const tc = themeRef.current ?? getTopoThemeColors();
    const updates = data.edges.map((e) => {
      const overlay = edgeOverlayProps(e);
      const fullLabel = overlay.label;
      const displayLabel = labelsVisible ? fullLabel : '';
      return {
        id: e.id,
        label: displayLabel,
        title: fullLabel || undefined,
        color: overlay.color,
        width: overlay.width,
        dashes: overlay.dashes,
        shadow: glow(overlay.shadowColor, 6),
        font: {
          size: labelsVisible ? 9 : 0,
          color: tc.edgeFont,
          strokeWidth: 2,
          strokeColor: tc.edgeFontStroke,
          align: 'middle',
        },
      } as VisEdge;
    });
    edgesDS.update(updates);
    network.redraw();
  }

  function refreshNodeStyles() {
    const network = networkRef.current;
    const nodesDS = nodesDSRef.current;
    if (!network || !nodesDS || !data) return;
    const tc = themeRef.current ?? getTopoThemeColors();
    const updates = data.nodes.map((n) => {
      const overlay = nodeOverlayProps(n, tc);
      const baseTitle = nodeTitle(n);
      const statusTitle =
        statusOverlay && typeof n.id === 'number'
          ? formatStatusTooltip(statusByHostRef.current.get(n.id))
          : '';
      return {
        id: n.id,
        color: overlay.color,
        borderWidth: overlay.borderWidth,
        shadow: glow(overlay.shadowColor, overlay.shadowSize),
        title: statusTitle ? `${baseTitle}\n\n${statusTitle}` : baseTitle,
      } as VisNode;
    });
    nodesDS.update(updates);
    network.redraw();
  }

  function formatStatusTooltip(s: TopologyHostStatus | undefined): string {
    if (!s) return '';
    const parts: string[] = [];
    if (s.audit_worst) {
      const counts = Object.entries(s.audit_counts)
        .map(([sev, n]) => `${sev}:${n}`)
        .join(' ');
      parts.push(`Audit: ${s.audit_worst.toUpperCase()} (${counts})`);
    }
    if (s.errors_open > 0) {
      parts.push(`Errors: ${s.errors_open} open${s.errors_worst ? ` (worst: ${s.errors_worst})` : ''}`);
    }
    if (s.drift_open > 0) {
      parts.push(`Drift: ${s.drift_open} open`);
    }
    return parts.join('\n');
  }

  function applyUtilizationUpdate(streamEdges: UtilizationStreamEdge[]) {
    if (!data) return;
    const utilMap: Record<string, UtilizationStreamEdge['utilization']> = {};
    for (const e of streamEdges) {
      const key = `${e.source_host_id}-${e.target_host_id}-${e.source_interface}`;
      utilMap[key] = e.utilization;
    }
    for (const edge of data.edges) {
      const key = `${edge.from_host_id ?? edge.from}-${edge.to_host_id ?? edge.to}-${edge.source_interface ?? ''}`;
      const incoming = utilMap[key];
      if (incoming) utilByEdgeRef.current.set(edge.id, incoming);
    }
    refreshEdgeStyles();
  }

  // ── Toolbar handlers ───────────────────────────────────────────────────

  async function handleRefresh() {
    qc.invalidateQueries({ queryKey: ['topology'] });
    qc.invalidateQueries({ queryKey: ['topology-positions'] });
    flash('Topology refreshed');
  }

  function handleFit() {
    networkRef.current?.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
  }

  async function handleResetPositions() {
    try {
      await deletePositions.mutateAsync();
      savedPositionsRef.current = {};
      if (layout === 'tidy') {
        renderGraph(data, {}, layout);
        flash('Node positions reset');
        return;
      }
      flash('Node positions reset - physics re-enabled');
      const network = networkRef.current;
      const nodesDS = nodesDSRef.current;
      if (network && nodesDS) {
        const ids = nodesDS.getIds();
        const updates = ids.map((id) => ({ id, fixed: false, physics: true } as never));
        nodesDS.update(updates as never);
        network.setOptions({ physics: { enabled: true } });
        network.once('stabilizationIterationsDone', () => {
          network.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
        });
        network.stabilize(250);
      }
    } catch (e) {
      flash(`Failed to reset positions: ${(e as Error).message}`);
    }
  }

  function togglePathMode() {
    if (pathMode) {
      clearPathMode();
      return;
    }
    if (!networkRef.current || !data?.nodes.length) return;
    setPathMode(true);
    setPathPicks([]);
    setPathSiteInput('');
    setPathSubnetInput('');
    setPathNote('');
    setDetailsNode(null);
    setDetailsEdge(null);
    // Search-highlight and path-mode share originalColorsRef; close the
    // search panel so we don't try to restore stale colors twice.
    if (searchPanelOpen) setSearchPanelOpen(false);
    restoreOriginalColors();
  }

  function toggleSearchPanel() {
    if (searchPanelOpen) {
      setSearchPanelOpen(false);
      return;
    }
    if (pathMode) clearPathMode();
    setSearchPanelOpen(true);
  }

  function clearPathMode() {
    setPathMode(false);
    setPathPicks([]);
    setPathSiteInput('');
    setPathSubnetInput('');
    setPathNote('');
    restoreOriginalColors();
  }

  // Add the pick to the path, or take it off when it is already on it.
  function togglePathPick(pick: PathPick) {
    const current = pathPicksRef.current;
    let next: PathPick[];
    if (current.some((p) => p.key === pick.key)) {
      next = current.filter((p) => p.key !== pick.key);
    } else if (current.length >= MAX_PATH_ENDPOINTS) {
      setPathNote(`A path connects up to ${MAX_PATH_ENDPOINTS} devices, sites or subnets. Remove one first.`);
      return;
    } else {
      next = [...current, pick];
    }
    pathPicksRef.current = next;
    setPathPicks(next);
    setPathNote('');
  }

  function addPathPick(pick: PathPick) {
    if (!pathPicksRef.current.some((p) => p.key === pick.key)) togglePathPick(pick);
  }

  function nodePick(nodeId: number | string): PathPick {
    const raw = nodeMetaRef.current.get(nodeId)?.raw;
    const site = raw?.meraki?.site_name;
    const label = raw?.label ?? String(nodeId);
    return { key: `n:${nodeId}`, node: nodeId, label: site && !label.includes(site) ? `${label} · ${site}` : label };
  }

  // `typed` is a finished entry (Enter) rather than a keystroke: then part of
  // a site name is enough, and an address typed here goes to the subnets.
  function handlePathSiteInput(value: string, typed = false) {
    const wanted = value.trim().toLowerCase();
    let site = wanted ? pathSiteList.find((s) => s.name.toLowerCase() === wanted) : undefined;
    if (!site && typed && wanted) {
      if (isAddressText(wanted)) {
        if (handlePathSubnetInput(value, true)) setPathSiteInput('');
        return;
      }
      const matches = pathSiteList.filter((s) => s.name.toLowerCase().includes(wanted));
      if (matches.length === 1) site = matches[0];
      else setPathNote(matches.length ? `${matches.length} sites match "${value.trim()}" - pick one from the list.` : `No site matches "${value.trim()}".`);
    }
    if (!site) {
      setPathSiteInput(value);
      return;
    }
    setPathSiteInput('');
    addPathPick(nodePick(site.gateway));
  }

  // `typed` is a finished entry (Enter) rather than a keystroke: then an
  // address or network is resolved to the subnet that contains it. Returns
  // whether a subnet was added.
  function handlePathSubnetInput(value: string, typed = false): boolean {
    const node = pathSubnets.owners.get(value.trim());
    const found = node !== undefined || typed ? findSubnets(value, pathSubnets.list) : [];
    if (found.length !== 1) {
      setPathSubnetInput(value);
      if (typed && value.trim()) {
        const sites = [...new Set(found.map((s) => s.site_name || s.name))];
        setPathNote(
          found.length
            ? `${value.trim()} is in ${found[0].cidr}, which exists at ${found.length} places (${sites.slice(0, 4).join(', ')}${sites.length > 4 ? ', ...' : ''}) - pick the one you mean from the subnet list.`
            : subnetsQuery.isPending
              ? 'Subnets are still loading - try again in a moment.'
              : `No collected subnet contains ${value.trim()}.`,
        );
      }
      return false;
    }
    const subnet = found[0];
    const owner = pathSubnets.owners.get(subnetOptionLabel(subnet));
    if (owner === undefined) return false;
    setPathSubnetInput('');
    // A typed address inside the subnet is kept: the trace matches rules against
    // it, and the security groups of the instance that has it.
    const typedAddress = isAddressText(value) && value.trim() !== subnet.cidr ? value.trim() : undefined;
    addPathPick({
      key: `s:${subnet.org_ref}:${typedAddress ?? subnet.cidr}:${subnet.node_id}`,
      node: owner,
      label: `${typedAddress ?? subnet.cidr} · ${subnet.site_name || subnet.name}`,
      subnet,
      address: typedAddress,
    });
    return true;
  }

  function pathLabel(nodeId: number | string): string {
    return nodeMetaRef.current.get(nodeId)?.raw.label ?? String(nodeId);
  }

  function applySearchHighlight(target: HighlightTarget | null) {
    const nodesDS = nodesDSRef.current;
    const edgesDS = edgesDSRef.current;
    if (!nodesDS || !edgesDS || !data) return;

    // Always reset to baseline first so successive searches don't accumulate
    // dimming, and entering search mode also clears any path-mode overlay.
    restoreOriginalColors();

    if (!target || target.nodeIds.length === 0) return;

    const hostSet = new Set<number | string>(target.nodeIds);
    // Build the (host,port) match set so we can light up the specific edge
    // the MAC/ARP entry was learned on -- not just the device.
    const portSet = new Set<string>();
    for (const p of target.ports) portSet.add(`${p.hostId}|${p.portName.toLowerCase()}`);

    const matchedEdges = new Set<number | string>();
    for (const e of data.edges) {
      // Edge counts as matched if either endpoint+port pair was in the
      // search hit set; falls back to either endpoint host being matched
      // (so VLAN highlights show all inter-device links between members).
      const fromHit = e.from_host_id != null && e.source_interface
        ? portSet.has(`${e.from_host_id}|${e.source_interface.toLowerCase()}`)
        : false;
      const toHit = e.to_host_id != null && e.target_interface
        ? portSet.has(`${e.to_host_id}|${e.target_interface.toLowerCase()}`)
        : false;
      const endpointHit =
        hostSet.has(e.from) && hostSet.has(e.to);
      if (fromHit || toHit || endpointHit) matchedEdges.add(e.id);
    }

    const tc = themeRef.current ?? getTopoThemeColors();
    originalColorsRef.current = { nodes: [], edges: [] };
    // One update per data set: thousands of single-item updates each make
    // vis-network rework the item and queue a redraw.
    const nodeUpdates: unknown[] = [];
    for (const node of nodesDS.get()) {
      const nid = node.id as number | string;
      originalColorsRef.current.nodes.push([nid, (node as never as { color: unknown }).color]);
      if (!hostSet.has(nid)) {
        nodeUpdates.push({ id: nid, color: tc.dimColor, opacity: 0.25 });
      } else {
        nodeUpdates.push({
          id: nid,
          borderWidth: 4,
          shadow: { enabled: true, color: tc.pathGlow, size: 20, x: 0, y: 0 },
        });
      }
    }
    nodesDS.update(nodeUpdates as never);
    const edgeUpdates: unknown[] = [];
    for (const edge of edgesDS.get()) {
      const eid = edge.id as number | string;
      originalColorsRef.current.edges.push([eid, (edge as never as { color: unknown }).color]);
      if (!matchedEdges.has(eid)) {
        edgeUpdates.push({ id: eid, color: tc.dimEdge, opacity: 0.15 });
      } else {
        edgeUpdates.push({
          id: eid,
          width: 4,
          shadow: { enabled: true, color: tc.pathGlow, size: 12, x: 0, y: 0 },
        });
      }
    }
    edgesDS.update(edgeUpdates as never);

    // Fit viewport to matching nodes so the operator's eye lands on them.
    const network = networkRef.current;
    if (network) {
      network.fit({
        nodes: target.nodeIds as never[],
        animation: { duration: 500, easingFunction: 'easeInOutQuad' },
      });
    }
  }

  function restoreOriginalColors() {
    const nodesDS = nodesDSRef.current;
    const edgesDS = edgesDSRef.current;
    const orig = originalColorsRef.current;
    if (!orig || !nodesDS || !edgesDS) return;
    nodesDS.update(orig.nodes.map(([id, color]) => ({ id, color, opacity: 1, borderWidth: 2.5 })) as never);
    edgesDS.update(orig.edges.map(([id, color]) => ({ id, color, opacity: 1 })) as never);
    originalColorsRef.current = null;
    pathRoutesRef.current.clear();
    syncTunnelVisibility();
    // Re-apply styled overlays (util / STP) so refresh restores any overlay
    // state that the dim pass blew away.
    refreshEdgeStyles();
    refreshNodeStyles();
  }

  function highlightPath(pathSet: Set<number | string>, pathEdgeIds: Set<number | string>) {
    const nodesDS = nodesDSRef.current;
    const edgesDS = edgesDSRef.current;
    if (!nodesDS || !edgesDS || !data) return;
    const tc = themeRef.current ?? getTopoThemeColors();
    originalColorsRef.current = { nodes: [], edges: [] };
    const nodeUpdates: unknown[] = [];
    for (const node of nodesDS.get()) {
      originalColorsRef.current.nodes.push([node.id as number | string, (node as never as { color: unknown }).color]);
      if (!pathSet.has(node.id as number | string)) {
        nodeUpdates.push({ id: node.id, color: tc.dimColor, opacity: 0.3 });
      } else {
        nodeUpdates.push({
          id: node.id,
          borderWidth: 4,
          shadow: { enabled: true, color: tc.pathGlow, size: 20, x: 0, y: 0 },
        });
      }
    }
    nodesDS.update(nodeUpdates as never);
    const edgeUpdates: unknown[] = [];
    for (const edge of edgesDS.get()) {
      originalColorsRef.current.edges.push([edge.id as number | string, (edge as never as { color: unknown }).color]);
      if (!pathEdgeIds.has(edge.id as number | string)) {
        edgeUpdates.push({ id: edge.id, color: tc.dimEdge, opacity: 0.15 });
      } else {
        // A path may run over a VPN tunnel that is not being drawn.
        const routed = routedEdgesRef.current.has(edge.id as number | string);
        if (routed) pathRoutesRef.current.add(edge.id as number | string);
        edgeUpdates.push({
          id: edge.id,
          width: 4,
          hidden: routed,
          shadow: { enabled: true, color: tc.pathGlow, size: 12, x: 0, y: 0 },
        });
      }
    }
    edgesDS.update(edgeUpdates as never);
  }

  async function handleScanStp() {
    try {
      const r = await stpScan.mutateAsync({
        groupId: groupFilter || null,
        vlanId: stpVlan,
        allVlans: stpAllVlans,
        maxVlans: 128,
      });
      const vlanScope = r.all_vlans
        ? `${r.vlans_scanned?.length ?? 0} VLANs`
        : `VLAN ${stpVlan}`;
      flash(`STP scan complete (${vlanScope}): ${r.ports_collected} ports from ${r.hosts_updated}/${r.hosts_scanned} hosts${r.errors ? ` (${r.errors} errors)` : ''}`);
      setStpBadge(r.unacknowledged_events ?? 0);
      if (stpOverlay) {
        const resp = await fetchTopologyStpState(groupFilter || null, null, stpAllVlans ? 1 : stpVlan, 20000);
        const map = new Map<string, StpState>();
        for (const row of resp.states ?? []) {
          map.set(stpPortKey(row.host_id, row.interface_name ?? ''), row);
        }
        stpStateRef.current = map;
        refreshEdgeStyles();
      }
    } catch (e) {
      flash(`STP scan failed: ${(e as Error).message}`);
    }
  }

  function handleExportPNG() {
    if (!networkRef.current) return flash('No topology to export');
    try {
      const groupName = groupsQuery.data?.find((g) => String(g.id) === groupFilter)?.name ?? 'All Groups';
      exportPNG(networkRef.current, groupName);
      flash('PNG exported');
    } catch (e) {
      flash(`Export failed: ${(e as Error).message}`);
    }
  }

  function handleExportJSON() {
    if (!data) return flash('No topology to export');
    try {
      exportJSON(data);
      flash('JSON exported');
    } catch (e) {
      flash(`Export failed: ${(e as Error).message}`);
    }
  }

  function handleExportSVG() {
    if (!networkRef.current || !data) return flash('No topology to export');
    try {
      const tc = themeRef.current ?? getTopoThemeColors();
      const groupName = groupsQuery.data?.find((g) => String(g.id) === groupFilter)?.name ?? 'All Groups';
      exportSVG(networkRef.current, data, groupName, tc);
      flash('SVG exported');
    } catch (e) {
      flash(`Export failed: ${(e as Error).message}`);
    }
  }

  function focusNode(nodeId: number | string) {
    const network = networkRef.current;
    if (!network) return;
    network.focus(nodeId as never, {
      scale: 1.5,
      animation: { duration: 600, easingFunction: 'easeInOutQuad' },
    });
    network.selectNodes([nodeId as never]);
    const meta = nodeMetaRef.current.get(nodeId);
    if (meta) setDetailsNode(meta.raw);
  }

  // Search results: instant local matches on identity fields, followed by
  // server-side deep matches inside Meraki details (VLANs, subnets, routes,
  // VPN peers, firewall rules, ports...), resolved back to nodes on the map.
  const searchResults = useMemo<SearchResult[]>(() => {
    const terms = search.trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (!terms.length || !data?.nodes.length) return [];
    const results: SearchResult[] = [];
    const seen = new Set<number | string>();
    for (const n of data.nodes) {
      const text = nodeSearchText(n);
      if (terms.every((t) => text.includes(t))) {
        results.push({ node: n });
        seen.add(n.id);
      }
    }
    // Deep hits belong to the debounced query; ignore them while it lags.
    if (deepSearch.data && debouncedSearch === search) {
      const byMerakiKey = new Map<string, TopologyNode>();
      for (const n of data.nodes) {
        if (n.meraki) byMerakiKey.set(merakiNodeKey(n.meraki.org_ref, n.meraki.node_id), n);
      }
      for (const hit of deepSearch.data.results) {
        const node = byMerakiKey.get(merakiNodeKey(hit.org_ref, hit.node_id));
        if (node && !seen.has(node.id)) {
          results.push({ node, snippet: hit.snippet });
          seen.add(node.id);
        }
      }
    }
    return results;
  }, [search, debouncedSearch, data, deepSearch.data]);

  function selectSearchResult(result: SearchResult) {
    setAppliedSearch(search);
    focusNode(result.node.id);
    setSearch('');
    setSearchResultsVisible(false);
  }

  // Light up every match at once (and dim the rest), like the MAC/IP/VLAN finder.
  function highlightAllSearchResults() {
    if (pathMode) clearPathMode();
    if (searchPanelOpen) setSearchPanelOpen(false);
    setAppliedSearch(search);
    setHighlightCount(searchResults.length);
    applySearchHighlight({ nodeIds: searchResults.map((r) => r.node.id), ports: [] });
    setSearchResultsVisible(false);
  }

  function clearSearchHighlight() {
    setHighlightCount(0);
    setAppliedSearch('');
    setSearch('');
    applySearchHighlight(null);
  }

  function handleSearchKey(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSearchHighlightIdx((i) => Math.min(i + 1, searchResults.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSearchHighlightIdx((i) => Math.max(i - 1, 0));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      // Enter on a picked row (or a lone match) jumps to it; Enter on the
      // bare query highlights every match on the map.
      if (searchHighlightIdx >= 0 && searchResults[searchHighlightIdx]) {
        selectSearchResult(searchResults[searchHighlightIdx]);
      } else if (searchResults.length === 1) {
        selectSearchResult(searchResults[0]);
      } else if (searchResults.length > 1) {
        highlightAllSearchResults();
      }
    } else if (e.key === 'Escape') {
      setSearchResultsVisible(false);
    }
  }

  return (
    <div style={{ position: 'relative' }}>
      <PageHelp
        pageKey="topology"
        title="Interactive Network Map"
        text="Visualize your network as an interactive graph. Drag nodes to rearrange, zoom in/out, and click devices to view details. Connections are discovered from device data (CDP/LLDP/OSPF/BGP) and, for Meraki organizations, Cato accounts, Cisco FMCs, AWS accounts, Azure subscriptions and GCP projects, from their APIs. Search finds devices by name or address and Meraki devices by anything collected for them - VLANs, subnets, routes, VPN peers, firewall rules. Sources lists everything that feeds the map and collects it again. Export HTML saves the whole map as one shareable interactive file."
      />

      {actionMsg && (
        <div className="card" style={{ padding: '0.5rem 0.85rem', marginBottom: '0.6rem', borderLeft: '3px solid var(--success)' }}>
          {actionMsg}
        </div>
      )}

      <div className="card" style={{ padding: '0.6rem 0.75rem', marginBottom: '0.75rem', display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'center' }}>
        <select className="form-select" style={{ minWidth: 160 }} value={groupFilter} onChange={(e) => setGroupFilter(e.target.value)}>
          <option value="">All Groups</option>
          {groupsQuery.data?.map((g) => (
            <option key={g.id} value={g.id}>{g.name}</option>
          ))}
        </select>
        <select className="form-select" style={{ minWidth: 170 }} value={layout} onChange={(e) => setLayout(e.target.value as LayoutMode)}>
          <option value="tidy">Tidy tree (top→bottom)</option>
          <option value="physics">Physics (force-directed)</option>
          <option value="circular">Circular</option>
          <option value="hierarchical-UD">Hierarchical (top→bottom)</option>
          <option value="hierarchical-DU">Hierarchical (bottom→top)</option>
          <option value="hierarchical-LR">Hierarchical (left→right)</option>
          <option value="hierarchical-RL">Hierarchical (right→left)</option>
        </select>
        {hasMeraki && (
          <select
            className="form-select"
            style={{ minWidth: 150 }}
            value={activeFilter}
            title="Which devices to show"
            onChange={(e) => setSourceFilter(e.target.value as SourceFilter)}
          >
            <option value="all">All sources</option>
            <option value="inventory">Inventory only</option>
            <option value="meraki">All integrations</option>
            {providersOnMap.map((p) => (
              <option key={p} value={`provider:${p}`}>{providerLabel(p)} only</option>
            ))}
          </select>
        )}

        <div style={{ position: 'relative' }} className="topology-search-wrap">
          <input
            type="text"
            className="form-input"
            placeholder={hasMeraki ? 'Search devices, IPs, VLANs, subnets, routes…' : 'Search nodes...'}
            style={{ minWidth: hasMeraki ? 300 : 200 }}
            value={search}
            onChange={(e) => { setSearch(e.target.value); setSearchResultsVisible(true); setSearchHighlightIdx(-1); }}
            onFocus={() => {
              if (searchBlurTimerRef.current) {
                clearTimeout(searchBlurTimerRef.current);
                searchBlurTimerRef.current = null;
              }
              setSearchResultsVisible(true);
            }}
            onBlur={() => {
              if (searchBlurTimerRef.current) clearTimeout(searchBlurTimerRef.current);
              searchBlurTimerRef.current = setTimeout(() => {
                searchBlurTimerRef.current = null;
                setSearchResultsVisible(false);
              }, 200);
            }}
            onKeyDown={handleSearchKey}
          />
          {searchResultsVisible && search && (
            <div style={{ position: 'absolute', top: '100%', left: 0, right: 0, zIndex: 10, background: 'var(--card-bg)', border: '1px solid var(--border)', borderRadius: '0.3rem', maxHeight: 340, overflowY: 'auto', marginTop: '0.2rem' }}>
              {searchResults.length > 1 && (
                <div
                  onMouseDown={(e) => { e.preventDefault(); highlightAllSearchResults(); }}
                  style={{ padding: '0.4rem 0.65rem', cursor: 'pointer', fontSize: '0.8rem', borderBottom: '1px solid var(--border)', color: 'var(--primary)' }}
                >
                  Highlight all {searchResults.length} matches on the map (Enter)
                </div>
              )}
              {searchResults.length === 0 ? (
                <div className="text-muted" style={{ padding: '0.5rem 0.75rem' }}>
                  {deepSearch.isFetching || debouncedSearch !== search ? 'Searching…' : 'No matches'}
                </div>
              ) : searchResults.slice(0, MAX_SEARCH_RESULTS).map((r, i) => (
                <div
                  key={String(r.node.id)}
                  onMouseDown={(e) => { e.preventDefault(); selectSearchResult(r); }}
                  style={{
                    padding: '0.4rem 0.65rem',
                    cursor: 'pointer',
                    background: i === searchHighlightIdx ? 'var(--bg-secondary)' : 'transparent',
                    fontSize: '0.85rem',
                  }}
                >
                  <div>{r.node.label}</div>
                  <div className="text-muted" style={{ fontSize: '0.75rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {r.snippet || [r.node.ip, r.node.meraki?.site_name || r.node.group_name].filter(Boolean).join(' · ')}
                  </div>
                </div>
              ))}
              {searchResults.length > MAX_SEARCH_RESULTS && (
                <div className="text-muted" style={{ padding: '0.4rem 0.65rem', fontSize: '0.75rem' }}>
                  {searchResults.length - MAX_SEARCH_RESULTS} more - refine the search or highlight all.
                </div>
              )}
            </div>
          )}
        </div>

        <button className="btn btn-primary btn-sm" onClick={() => setSourcesOpen(true)} title="Everything that feeds the map - neighbor discovery, Meraki, Cato, Cisco FMC, AWS, Azure, GCP: add, collect, history">Sources</button>
        <button className="btn btn-secondary btn-sm" onClick={handleRefresh}>Refresh</button>
        <button className="btn btn-secondary btn-sm" onClick={handleFit}>Fit</button>
        <button className={`btn btn-sm ${pathMode ? 'btn-primary' : 'btn-secondary'}`} onClick={togglePathMode} title="Pick devices or sites and see how they reach one another">{pathMode ? 'Exit Path' : 'Path Mode'}</button>
        <button className={`btn btn-sm ${searchPanelOpen ? 'btn-primary' : 'btn-secondary'}`} onClick={toggleSearchPanel}>{searchPanelOpen ? 'Close Search' : 'Find MAC/IP/VLAN'}</button>
        <button className={`btn btn-sm ${labelsVisible ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setLabelsVisible((v) => !v)}>Labels</button>
        {tunnelCount > 0 && (
          <button
            className={`btn btn-sm ${showAllTunnels ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setTunnelPref(!showAllTunnels)}
            title={
              showAllTunnels
                ? `Showing all ${tunnelCount} VPN tunnels. Click to show only the tunnels of the selected device.`
                : `Showing only the VPN tunnels of the selected device. Click to draw all ${tunnelCount}.`
            }
          >
            VPN Tunnels
          </button>
        )}
        <button className={`btn btn-sm ${utilOverlay ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setUtilOverlay((v) => !v)}>Util Overlay</button>
        <button className={`btn btn-sm ${stpOverlay ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setStpOverlay((v) => !v)}>STP Overlay</button>
        <button className={`btn btn-sm ${statusOverlay ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setStatusOverlay((v) => !v)}>Status Overlay</button>
        <button className="btn btn-secondary btn-sm" onClick={handleScanStp} disabled={stpScan.isPending}>{stpScan.isPending ? 'Scanning…' : 'Scan STP'}</button>
        <button className="btn btn-secondary btn-sm" onClick={() => setStpEventsOpen(true)}>
          STP Events {stpBadge > 0 && <span className="badge badge-danger" style={{ marginLeft: '0.25rem' }}>{stpBadge > 99 ? '99+' : stpBadge}</span>}
        </button>
        <button className="btn btn-secondary btn-sm" onClick={() => setChangesOpen(true)}>
          Changes {changeBadge > 0 && <span className="badge badge-warning" style={{ marginLeft: '0.25rem' }}>{changeBadge > 99 ? '99+' : changeBadge}</span>}
        </button>
        <button className="btn btn-secondary btn-sm" onClick={handleResetPositions}>Reset Positions</button>
        <button className="btn btn-secondary btn-sm" onClick={() => setSettingsOpen((v) => !v)}>Settings</button>
        <ExportMenu
          onPNG={handleExportPNG}
          onSVG={handleExportSVG}
          onJSON={handleExportJSON}
          htmlDownloadUrl={topologyExportUrl(groupId, true)}
          htmlOpenUrl={topologyExportUrl(groupId)}
        />
      </div>

      {highlightCount > 0 && (
        <div className="card" style={{ padding: '0.5rem 0.85rem', marginBottom: '0.6rem', borderLeft: '3px solid var(--primary)' }}>
          {highlightCount} device{highlightCount === 1 ? '' : 's'} matching “{appliedSearch}” highlighted. Click one to see the matching details.
          <button type="button" className="btn btn-sm btn-secondary" onClick={clearSearchHighlight} style={{ marginLeft: '0.6rem' }}>Clear</button>
        </div>
      )}

      {(stpOverlay || stpScan.isPending) && (
        <div className="card" style={{ padding: '0.5rem 0.75rem', marginBottom: '0.6rem', display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <label style={{ display: 'flex', gap: '0.4rem', alignItems: 'center', fontSize: '0.85rem' }}>
            <input type="checkbox" checked={stpAllVlans} onChange={(e) => setStpAllVlans(e.target.checked)} />
            All VLANs
          </label>
          <label style={{ display: 'flex', gap: '0.4rem', alignItems: 'center', fontSize: '0.85rem' }}>
            VLAN
            <input
              type="number"
              className="form-input"
              style={{ width: 80 }}
              min={1}
              max={4094}
              value={stpVlan}
              disabled={stpAllVlans}
              onChange={(e) => setStpVlan(Math.max(1, Math.min(4094, parseInt(e.target.value, 10) || 1)))}
            />
          </label>
        </div>
      )}

      {settingsOpen && (
        <div className="card" style={{ padding: '0.6rem 0.75rem', marginBottom: '0.6rem', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.75rem' }}>
          <label style={{ fontSize: '0.85rem' }}>
            Node Spacing: {spacing}
            <input type="range" min={120} max={400} value={spacing} onChange={(e) => setSpacing(parseInt(e.target.value, 10))} style={{ width: '100%' }} />
          </label>
          <label style={{ fontSize: '0.85rem' }}>
            Repulsion: {repulsion}
            <input type="range" min={2000} max={20000} step={500} value={repulsion} onChange={(e) => setRepulsion(parseInt(e.target.value, 10))} style={{ width: '100%' }} />
          </label>
          <label style={{ fontSize: '0.85rem' }}>
            Edge Length: {edgeLen}
            <input type="range" min={120} max={500} value={edgeLen} onChange={(e) => setEdgeLen(parseInt(e.target.value, 10))} style={{ width: '100%' }} />
          </label>
        </div>
      )}

      {pathMode && (
        <div className="card" style={{ padding: '0.5rem 0.85rem', marginBottom: '0.6rem', borderLeft: '3px solid var(--primary)', fontSize: '0.85rem' }}>
          <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center', flexWrap: 'wrap' }}>
            <strong>Path</strong>
            <span className="text-muted">
              Click two or more devices on the map{pathSiteList.length ? ', or add sites and subnets,' : ''} to see how they reach one another.
            </span>
            {pathSiteList.length > 0 && (
              <>
                <input
                  className="form-input"
                  list="topology-path-sites"
                  placeholder="Add a site…"
                  aria-label="Add a site to the path"
                  title="Pick a site from the list, or type part of its name and press Enter"
                  value={pathSiteInput}
                  onChange={(e) => handlePathSiteInput(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') handlePathSiteInput(e.currentTarget.value, true); }}
                  style={{ minWidth: 200 }}
                />
                <datalist id="topology-path-sites">
                  {pathSiteList.map((s) => <option key={s.key} value={s.name} />)}
                </datalist>
                <input
                  className="form-input"
                  list="topology-path-subnets"
                  placeholder={subnetsQuery.isPending ? 'Loading subnets…' : 'Add a subnet or IP address…'}
                  aria-label="Add a subnet to the path"
                  title="Pick a subnet from the list, or type an IP address or network and press Enter"
                  value={pathSubnetInput}
                  onChange={(e) => handlePathSubnetInput(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') handlePathSubnetInput(e.currentTarget.value, true); }}
                  style={{ minWidth: 260 }}
                />
                <datalist id="topology-path-subnets">
                  {pathSubnets.list.map((s) => {
                    const text = subnetOptionLabel(s);
                    return <option key={`${s.org_ref}|${s.node_id}|${s.cidr}`} value={text} />;
                  })}
                </datalist>
              </>
            )}
            {pathHasTraceLeg && (
              <input
                className="form-input"
                placeholder="Traffic: any, or tcp/443"
                aria-label="Traffic traced through the routes, policies and NAT on the path"
                title="Traffic the trace is asked about, from the first of two picks to the second: tcp/443, udp/53, icmp, or empty for any traffic"
                value={pathTraffic}
                onChange={(e) => setPathTraffic(e.target.value)}
                aria-invalid={trafficFilter === null}
                style={{ width: 190, borderColor: trafficFilter === null ? 'var(--danger)' : undefined }}
              />
            )}
            <button type="button" className="btn btn-sm btn-secondary" onClick={() => { setPathPicks([]); setPathNote(''); }} disabled={!pathPicks.length}>Clear</button>
            <button type="button" className="btn btn-sm btn-secondary" onClick={clearPathMode}>Exit</button>
          </div>
          {pathNote && (
            <div role="status" style={{ marginTop: '0.45rem', color: 'var(--warning, #f59f00)' }}>{pathNote}</div>
          )}
          {pathPicks.length === 1 && (
            <div className="text-muted" style={{ marginTop: '0.45rem' }}>Add one more to see the path.</div>
          )}
          {pathPicks.length > 0 && (
            <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', marginTop: '0.45rem' }}>
              {pathPicks.map((pick) => (
                <button key={pick.key} type="button" className="btn btn-sm btn-secondary" onClick={() => togglePathPick(pick)} title="Remove from the path">
                  {pick.label} ×
                </button>
              ))}
            </div>
          )}
          {pathResult.legs.map((leg) => (
            <div key={legKey(leg)} style={{ marginTop: '0.35rem' }}>
              {(leg.from.subnet || leg.to.subnet) && (
                <strong>{leg.from.address ?? leg.from.subnet?.cidr ?? leg.from.label} ↔ {leg.to.address ?? leg.to.subnet?.cidr ?? leg.to.label}: </strong>
              )}
              {/* A traced leg lists the hops of its trace (PathTrace below) instead of the drawn path. */}
              {leg.sameDevice ? (
                <>Same device - routed locally by {pathLabel(leg.from.node)}.</>
              ) : leg.path && traceHighlights[legKey(leg)]?.nodeIds.size ? null : leg.path ? (
                <>
                  {leg.path.map((id) => pathLabel(id)).join(' → ')}{' '}
                  <span className="text-muted">({leg.path.length - 1} hop{leg.path.length - 1 !== 1 ? 's' : ''})</span>
                </>
              ) : (
                <span style={{ color: 'var(--danger)' }}>
                  {pathLabel(leg.from.node)} and {pathLabel(leg.to.node)}: no path over links that are up.
                </span>
              )}
              {leg.notes.map((note) => (
                <div key={note} style={{ color: 'var(--warning, #f59f00)' }}>⚠ {note}</div>
              ))}
              {(() => {
                const key = legKey(leg);
                const query = trafficFilter ? pathTraceQuery(leg.from, leg.to, trafficFilter) : null;
                if (query) {
                  return (
                    <PathTrace
                      forward={query}
                      backward={reverseTraceQuery(query)}
                      onHighlight={(highlight) => setLegHighlight(key, highlight)}
                    />
                  );
                }
                const note = leg.sameDevice ? null : uncheckedTraceNote(leg.from, leg.to);
                return note && <div className="text-muted">ⓘ {note}</div>;
              })()}
            </div>
          ))}
          {pathResult.legs.length > 0 && (
            <div className="text-muted" style={{ marginTop: '0.35rem', fontSize: '0.78rem' }}>
              The path drawn is the shortest way over the cables, uplinks and VPN tunnels on the map that are up: it shows how
              the ends are joined, not the route each device picks.
              {pathHasTraceLeg && ' A traced leg lists the hops of its trace instead.'} A subnet is placed on the device that
              owns it (appliance, L3 switch, VPC or VPN peer).
              {pathHasTraceLeg &&
                ' Between two subnets or addresses the server traces the flow hop by hop and lists, at every device, the policies, ACLs, security groups, NAT rules and routes it hits, for the request and for the replies, and says whether routing is asymmetric. Reverse swaps the ends. Anything a source does not collect is reported as unknown, never as allowed.'}
            </div>
          )}
        </div>
      )}

      {topologyQuery.isPending && <div className="text-muted">Loading topology…</div>}
      {topologyQuery.error && <div style={{ color: 'var(--danger)' }}>Error: {(topologyQuery.error as Error).message}</div>}

      {data && !data.nodes.length && (
        <div className="card" style={{ padding: '1.5rem', textAlign: 'center' }}>
          <p className="text-muted" style={{ marginTop: 0 }}>No topology data. Open Sources to discover the neighbors of your inventory devices, or to add a Meraki organization, a Cato account, a Cisco FMC, an AWS account, an Azure subscription or a GCP project.</p>
          <button className="btn btn-primary btn-sm" onClick={() => setSourcesOpen(true)}>Sources</button>
        </div>
      )}

      <div style={{ position: 'relative', height: 'calc(100vh - 280px)', minHeight: 460, border: '1px solid var(--border)', borderRadius: '0.5rem', overflow: 'hidden', display: data && data.nodes.length ? 'block' : 'none' }}>
        <div ref={containerRef} id="topology-canvas" style={{ width: '100%', height: '100%' }} />
        {searchPanelOpen && (
          <TopologySearchPanel
            onHighlight={stableApplySearchHighlight}
            resolveMeraki={resolveMerakiNode}
            onClose={() => setSearchPanelOpen(false)}
          />
        )}
        {detailsEdge && data && !detailsNode && (
          <EdgeDetails
            edge={detailsEdge}
            fromNode={data.nodes.find((n) => n.id === detailsEdge.from)}
            toNode={data.nodes.find((n) => n.id === detailsEdge.to)}
            onClose={() => setDetailsEdge(null)}
          />
        )}
        {detailsNode && data && (
          <NodeDetails
            node={detailsNode}
            edges={data.edges}
            allNodes={data.nodes}
            stpStateByPort={stpStateRef.current}
            onClose={() => setDetailsNode(null)}
            searchText={appliedSearch}
            onAddToInventory={(n) => setAddInvTarget(n)}
            onCategoryUpdated={(hostId, newCategory) => {
              // Write to the unfiltered graph: `data` may be a source-filtered view.
              if (!rawData) return;
              const target = rawData.nodes.find((n) => n.id === hostId);
              if (!target) return;
              const updatedNode = { ...target, device_category: newCategory };
              qc.setQueryData(['topology', groupId ?? null], {
                ...rawData,
                nodes: rawData.nodes.map((n) => (n.id === hostId ? updatedNode : n)),
              });
              const iconUrl = nodeIconUrl(updatedNode);
              const nodesDS = nodesDSRef.current;
              nodesDS?.update({
                id: hostId,
                shape: iconUrl ? 'circularImage' : nodeShape(updatedNode.device_type),
                image: iconUrl,
              } as never);
              flash(`Role updated to ${newCategory || '(auto)'}`);
            }}
          />
        )}
      </div>

      {data && data.nodes.length > 0 && (
        <div className="topology-legend">
          <span className="topology-legend-item"><span className="topology-legend-dot topology-legend-dot-inventory" /> Inventory Device</span>
          <span className="topology-legend-item"><span className="topology-legend-dot topology-legend-dot-dashed" /> External Neighbor</span>
          <span className="topology-legend-item"><span className="topology-legend-line topology-legend-line-cdp" /> CDP</span>
          <span className="topology-legend-item"><span className="topology-legend-line topology-legend-line-lldp" /> LLDP</span>
          <span className="topology-legend-item"><span className="topology-legend-line topology-legend-line-ospf" /> OSPF</span>
          <span className="topology-legend-item"><span className="topology-legend-line topology-legend-line-bgp" /> BGP</span>
          {hasMeraki && activeFilter !== 'inventory' && (
            <>
              <span className="topology-legend-item"><span className="topology-legend-dot" style={{ background: '#8bc34a' }} /> Meraki / Cato / Cisco FMC / AWS / Azure / GCP</span>
              <span className="topology-legend-item"><span className="topology-legend-dot" style={{ background: '#ba68c8' }} /> VPN Tunnel</span>
              <span className="topology-legend-item"><span className="topology-legend-dot" style={{ background: '#ff9800' }} /> Cloud Attachment</span>
              <span className="topology-legend-item"><span className="topology-legend-dot" style={{ background: '#4fc3f7' }} /> WAN Uplink</span>
              <span className="topology-legend-item"><span className="topology-legend-dot" style={{ background: '#9e9e9e' }} /> Managed by FMC</span>
              <span className="topology-legend-item"><span className="topology-legend-dot" style={{ background: '#f44336' }} /> Offline / Unreachable</span>
            </>
          )}
          {utilOverlay && (
            <span className="topology-legend-item">
              <span className="topology-legend-gradient" /> Utilization (links + IPAM nodes, 0–100%)
            </span>
          )}
          {stpOverlay && (
            <>
              <span className="topology-legend-item"><span className="topology-legend-line topology-legend-line-stp-fwd" /> STP Forwarding</span>
              <span className="topology-legend-item"><span className="topology-legend-line topology-legend-line-stp-learn" /> STP Learning</span>
              <span className="topology-legend-item"><span className="topology-legend-line topology-legend-line-stp-block" /> STP Blocked</span>
            </>
          )}
          {statusOverlay && (
            <>
              <span className="topology-legend-item"><span className="topology-legend-dot" style={{ background: '#f44336' }} /> Critical</span>
              <span className="topology-legend-item"><span className="topology-legend-dot" style={{ background: '#ff7043' }} /> High</span>
              <span className="topology-legend-item"><span className="topology-legend-dot" style={{ background: '#ffc107' }} /> Medium / Drift</span>
              <span className="topology-legend-item"><span className="topology-legend-dot" style={{ background: '#29b6f6' }} /> Low / Info</span>
              {overlayStatusQuery.isPending && (
                <span className="text-muted" style={{ marginLeft: 'auto', fontSize: '0.8rem' }}>
                  Loading status…
                </span>
              )}
              {overlayStatusQuery.data && overlayStatusQuery.data.hosts.length === 0 && (
                <span className="text-muted" style={{ marginLeft: 'auto', fontSize: '0.8rem' }}>
                  All devices clean - no open findings, drift, or errors.
                </span>
              )}
            </>
          )}
          {utilOverlay && data.edges.length > 0 && data.edges.every((e) => e.utilization == null) && (
            <span className="text-muted" style={{ marginLeft: 'auto', fontSize: '0.8rem' }}>
              No utilization data - needs SNMP interface polling with two counter samples and if_speed_mbps set.
            </span>
          )}
        </div>
      )}

      {addInvTarget && (
        <AddToInventoryModal
          isOpen={!!addInvTarget}
          hostname={addInvTarget.label}
          ip={addInvTarget.ip ?? ''}
          extNodeId={addInvTarget.id}
          onClose={() => setAddInvTarget(null)}
          onAdded={({ groupId: _g, groupName, newHostId, extNodeId }) => {
            const network = networkRef.current;
            if (network && extNodeId != null) {
              try {
                const positionsAfter = network.getPositions([extNodeId as never]);
                const pos = positionsAfter[extNodeId as never];
                if (pos) {
                  const newKey = String(newHostId);
                  savedPositionsRef.current[newKey] = { x: pos.x, y: pos.y };
                  delete savedPositionsRef.current[String(extNodeId)];
                  savePositions.mutate({
                    [newKey]: { x: pos.x, y: pos.y },
                    [String(extNodeId)]: null,
                  });
                }
              } catch {
                /* ignore */
              }
            }
            qc.invalidateQueries({ queryKey: ['topology'] });
            qc.invalidateQueries({ queryKey: ['inventory-groups'] });
            setDetailsNode(null);
            flash(`Added ${addInvTarget.label} (${addInvTarget.ip}) to ${groupName}`);
          }}
        />
      )}

      <DiscoveryProgressModal
        isOpen={discoveryOpen}
        groupId={groupId}
        onClose={() => setDiscoveryOpen(false)}
        onComplete={() => {
          qc.invalidateQueries({ queryKey: ['topology'] });
          qc.invalidateQueries({ queryKey: ['meraki', 'sources'] });
        }}
      />
      <SourcesModal
        isOpen={sourcesOpen}
        onClose={() => setSourcesOpen(false)}
        onDiscoverNeighbors={() => setDiscoveryOpen(true)}
      />
      <ChangesModal
        isOpen={changesOpen}
        onClose={() => setChangesOpen(false)}
        onAcknowledged={() => {
          setChangeBadge(0);
          fetchTopologyChanges(true, 1).catch(() => {});
        }}
      />
      <StpEventsModal
        isOpen={stpEventsOpen}
        onClose={() => setStpEventsOpen(false)}
        onAcknowledged={() => setStpBadge(0)}
      />
    </div>
  );
}
