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
  type TopologyEdge,
  type TopologyHostStatus,
  type TopologyNode,
  type UtilizationStreamEdge,
} from '@/api/topology';
import { PageHelp } from '@/components/PageHelp';
import { AddToInventoryModal } from './AddToInventoryModal';
import { ChangesModal } from './ChangesModal';
import { DiscoveryProgressModal } from './DiscoveryProgressModal';
import { exportJSON, exportPNG, exportSVG } from './exporters';
import {
  abbreviateInterface,
  bfsShortestPath,
  edgeProtocolColor,
  getTopoThemeColors,
  nodeColor,
  nodeIconUrl,
  nodeShape,
  nodeTitle,
  stpPortKey,
  stpStyle,
  utilColor,
  utilShadow,
  type TopoThemeColors,
} from './helpers';
import { EdgeDetails } from './EdgeDetails';
import { NodeDetails } from './NodeDetails';
import { StpEventsModal } from './StpEventsModal';
import {
  TopologySearchPanel,
  type HighlightTarget,
} from './TopologySearchPanel';

type LayoutMode = 'physics' | 'circular' | 'hierarchical-UD' | 'hierarchical-DU' | 'hierarchical-LR' | 'hierarchical-RL';

interface NodeMeta {
  raw: TopologyNode;
  circularX?: number;
  circularY?: number;
}

interface EdgeMeta {
  raw: TopologyEdge;
  roundness: number;
}

export function Topology() {
  const qc = useQueryClient();
  const [groupFilter, setGroupFilter] = useState<string>('');
  const [layout, setLayout] = useState<LayoutMode>('physics');
  const [labelsVisible, setLabelsVisible] = useState(false);
  const [utilOverlay, setUtilOverlay] = useState(false);
  const [stpOverlay, setStpOverlay] = useState(false);
  const [stpVlan, setStpVlan] = useState(1);
  const [stpAllVlans, setStpAllVlans] = useState(false);
  const [pathMode, setPathMode] = useState(false);
  const [pathSource, setPathSource] = useState<number | string | null>(null);
  const [pathStatus, setPathStatus] = useState('');
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

  const data = topologyQuery.data;
  const positions = positionsQuery.data;
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
  useEffect(() => {
    if (data?.unacknowledged_changes != null) setChangeBadge(data.unacknowledged_changes);
  }, [data?.unacknowledged_changes]);

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
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
  }, [stpOverlay, stpVlan, stpAllVlans, groupFilter]);

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

  function buildVisNode(n: TopologyNode, savedPos: Record<string, { x: number; y: number }>, circularXY?: { x: number; y: number }): VisNode {
    const tc = themeRef.current ?? getTopoThemeColors();
    const overlay = nodeOverlayProps(n, tc);
    const iconUrl = nodeIconUrl(n);
    const node: VisNode = {
      id: n.id as never,
      label: n.label,
      title: nodeTitle(n),
      shape: iconUrl ? 'circularImage' : nodeShape(n.device_type),
      image: iconUrl,
      color: overlay.color,
      size: n.in_inventory ? 25 : 18,
      borderWidth: overlay.borderWidth,
      borderWidthSelected: 4,
      shapeProperties: { borderDashes: n.in_inventory ? false : [5, 5] },
      shadow: { enabled: true, color: overlay.shadowColor, size: overlay.shadowSize, x: 0, y: 0 },
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
    } else if (circularXY) {
      (node as Record<string, unknown>).x = circularXY.x;
      (node as Record<string, unknown>).y = circularXY.y;
    }
    return node;
  }

  function nodeOverlayProps(n: TopologyNode, tc: TopoThemeColors) {
    const baseColor = nodeColor(n, tc);
    const baseBorder = n.in_inventory ? 2.5 : 1.5;
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
      shadowSize: n.in_inventory ? 18 : 8,
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
      : false;
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
        : (utilColorOverride || (statusHex ? { color: statusHex, highlight: statusHex, hover: statusHex, opacity: 0.9 } : edgeProtocolColor(edge.protocol, tc))),
      width: stpStl ? Math.max(utilWidth, stpStl.width) : (statusHex ? Math.max(utilWidth, 3) : utilWidth),
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
      shadow: { enabled: true, color: overlay.shadowColor, size: 6, x: 0, y: 0 },
      font: { size: 9, color: tc.edgeFont, strokeWidth: 2, strokeColor: tc.edgeFontStroke, align: 'middle' },
      smooth: { type: 'continuous', roundness, enabled: true },
      title: fullLabel || undefined,
    } as VisEdge;
  }

  function renderGraph(d: typeof data, savedPos: Record<string, { x: number; y: number }>, mode: LayoutMode) {
    if (!d || !containerRef.current) return;
    themeRef.current = getTopoThemeColors();

    nodeMetaRef.current = buildNodeMeta(d);
    edgeMetaRef.current = assignParallelEdgeRoundness(d.edges);

    const isHier = mode.startsWith('hierarchical-');
    const isCircular = mode === 'circular';
    const allPinned = d.nodes.length > 0 && d.nodes.every((n) => savedPos[String(n.id)]);
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
        enabled: isCircular ? false : usePhysics,
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
        hover: true,
        tooltipDelay: 150,
        navigationButtons: false,
        keyboard: { enabled: true },
        zoomSpeed: 0.6,
      },
      layout: layoutConfig,
      edges: { smooth: { enabled: true, type: 'continuous', roundness: 0.4 } },
    };

    if (networkRef.current) networkRef.current.destroy();
    networkRef.current = new Network(containerRef.current, { nodes, edges }, options);
    nodesDSRef.current = nodes;
    edgesDSRef.current = edges;

    networkRef.current.on('click', (params) => {
      if (pathModeRef.current && params.nodes.length > 0) {
        handlePathClick(params.nodes[0]);
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
        setDetailsNode(null);
        setDetailsEdge(null);
      }
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
    });

    networkRef.current.on('oncontext', (params) => {
      params.event.preventDefault();
      if (!params.nodes || !params.nodes.length) return;
      const nid = params.nodes[0];
      const key = String(nid);
      if (savedPositionsRef.current[key]) {
        delete savedPositionsRef.current[key];
        nodes.update({ id: nid, fixed: false, physics: true } as never);
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
    } else if (allPinned || isCircular) {
      setTimeout(() => {
        networkRef.current?.fit({ animation: { duration: 300, easingFunction: 'easeInOutQuad' } });
      }, 50);
    }
  }

  // Keep pathMode/source in refs so the click handler always sees the latest.
  const pathModeRef = useRef(pathMode);
  const pathSourceRef = useRef(pathSource);
  useEffect(() => { pathModeRef.current = pathMode; }, [pathMode]);
  useEffect(() => { pathSourceRef.current = pathSource; }, [pathSource]);

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
        shadow: { enabled: true, color: overlay.shadowColor, size: 6, x: 0, y: 0 },
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
        shadow: { enabled: true, color: overlay.shadowColor, size: overlay.shadowSize, x: 0, y: 0 },
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
    setPathSource(null);
    setPathStatus('Click a source node...');
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
    setPathSource(null);
    setPathStatus('');
    const nodesDS = nodesDSRef.current;
    const edgesDS = edgesDSRef.current;
    const orig = originalColorsRef.current;
    if (orig && nodesDS && edgesDS) {
      for (const [id, color] of orig.nodes) {
        nodesDS.update({ id, color, opacity: 1 } as never);
      }
      for (const [id, color] of orig.edges) {
        edgesDS.update({ id, color, opacity: 1 } as never);
      }
      originalColorsRef.current = null;
    }
  }

  function handlePathClick(nodeId: number | string) {
    const nodesDS = nodesDSRef.current;
    const edgesDS = edgesDSRef.current;
    if (!nodesDS || !edgesDS || !data) return;
    if (!pathSourceRef.current) {
      setPathSource(nodeId);
      const meta = nodeMetaRef.current.get(nodeId);
      const label = meta?.raw.label ?? String(nodeId);
      setPathStatus(`Source: ${label}  -  click a destination node...`);
      nodesDS.update({ id: nodeId, borderWidth: 4 } as never);
      return;
    }
    const targetId = nodeId;
    if (targetId === pathSourceRef.current) return;

    const path = bfsShortestPath(pathSourceRef.current, targetId, data.edges);
    if (!path) {
      flash('No path found between these nodes.');
      clearPathMode();
      return;
    }

    highlightPath(path);
    const srcLabel = nodeMetaRef.current.get(pathSourceRef.current)?.raw.label ?? '';
    const tgtLabel = nodeMetaRef.current.get(targetId)?.raw.label ?? '';
    setPathStatus(`Path: ${srcLabel} → ${tgtLabel}  (${path.length - 1} hop${path.length - 1 !== 1 ? 's' : ''})`);
    setPathMode(false);
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
    for (const node of nodesDS.get()) {
      const nid = node.id as number | string;
      originalColorsRef.current.nodes.push([nid, (node as never as { color: unknown }).color]);
      if (!hostSet.has(nid)) {
        nodesDS.update({ id: nid, color: tc.dimColor, opacity: 0.25 } as never);
      } else {
        nodesDS.update({
          id: nid,
          borderWidth: 4,
          shadow: { enabled: true, color: tc.pathGlow, size: 20, x: 0, y: 0 },
        } as never);
      }
    }
    for (const edge of edgesDS.get()) {
      const eid = edge.id as number | string;
      originalColorsRef.current.edges.push([eid, (edge as never as { color: unknown }).color]);
      if (!matchedEdges.has(eid)) {
        edgesDS.update({ id: eid, color: tc.dimEdge, opacity: 0.15 } as never);
      } else {
        edgesDS.update({
          id: eid,
          width: 4,
          shadow: { enabled: true, color: tc.pathGlow, size: 12, x: 0, y: 0 },
        } as never);
      }
    }

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
    for (const [id, color] of orig.nodes) {
      nodesDS.update({ id, color, opacity: 1, borderWidth: 2.5 } as never);
    }
    for (const [id, color] of orig.edges) {
      edgesDS.update({ id, color, opacity: 1 } as never);
    }
    originalColorsRef.current = null;
    // Re-apply styled overlays (util / STP) so refresh restores any overlay
    // state that the dim pass blew away.
    refreshEdgeStyles();
    refreshNodeStyles();
  }

  function highlightPath(path: (number | string)[]) {
    const nodesDS = nodesDSRef.current;
    const edgesDS = edgesDSRef.current;
    if (!nodesDS || !edgesDS || !data) return;
    const pathSet = new Set(path);
    const pathEdgeIds = new Set<number | string>();
    for (let i = 0; i < path.length - 1; i++) {
      const a = path[i];
      const b = path[i + 1];
      const matches = data.edges.filter(
        (e) => (e.from === a && e.to === b) || (e.from === b && e.to === a),
      );
      for (const edge of matches) pathEdgeIds.add(edge.id);
    }
    const tc = themeRef.current ?? getTopoThemeColors();
    originalColorsRef.current = { nodes: [], edges: [] };
    for (const node of nodesDS.get()) {
      originalColorsRef.current.nodes.push([node.id as number | string, (node as never as { color: unknown }).color]);
      if (!pathSet.has(node.id as number | string)) {
        nodesDS.update({ id: node.id, color: tc.dimColor, opacity: 0.3 } as never);
      } else {
        nodesDS.update({
          id: node.id,
          borderWidth: 4,
          shadow: { enabled: true, color: tc.pathGlow, size: 20, x: 0, y: 0 },
        } as never);
      }
    }
    for (const edge of edgesDS.get()) {
      originalColorsRef.current.edges.push([edge.id as number | string, (edge as never as { color: unknown }).color]);
      if (!pathEdgeIds.has(edge.id as number | string)) {
        edgesDS.update({ id: edge.id, color: tc.dimEdge, opacity: 0.15 } as never);
      } else {
        edgesDS.update({
          id: edge.id,
          width: 4,
          shadow: { enabled: true, color: tc.pathGlow, size: 12, x: 0, y: 0 },
        } as never);
      }
    }
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

  // Search results
  const searchResults = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q || !data?.nodes.length) return [];
    return data.nodes.filter(
      (n) => (n.label ?? '').toLowerCase().includes(q) || (n.ip ?? '').includes(q),
    ).slice(0, 12);
  }, [search, data]);

  function handleSearchKey(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSearchHighlightIdx((i) => Math.min(i + 1, searchResults.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSearchHighlightIdx((i) => Math.max(i - 1, 0));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const idx = searchHighlightIdx >= 0 ? searchHighlightIdx : 0;
      const match = searchResults[idx];
      if (match) {
        focusNode(match.id);
        setSearch('');
        setSearchResultsVisible(false);
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
        text="Visualize your network as an interactive graph. Drag nodes to rearrange, zoom in/out, and click devices to view details. Connections are discovered from device data."
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
          <option value="physics">Physics (force-directed)</option>
          <option value="circular">Circular</option>
          <option value="hierarchical-UD">Hierarchical (top→bottom)</option>
          <option value="hierarchical-DU">Hierarchical (bottom→top)</option>
          <option value="hierarchical-LR">Hierarchical (left→right)</option>
          <option value="hierarchical-RL">Hierarchical (right→left)</option>
        </select>

        <div style={{ position: 'relative' }} className="topology-search-wrap">
          <input
            type="text"
            className="form-input"
            placeholder="Search nodes..."
            style={{ minWidth: 200 }}
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
            <div style={{ position: 'absolute', top: '100%', left: 0, right: 0, zIndex: 10, background: 'var(--card-bg)', border: '1px solid var(--border)', borderRadius: '0.3rem', maxHeight: 240, overflowY: 'auto', marginTop: '0.2rem' }}>
              {searchResults.length === 0 ? (
                <div className="text-muted" style={{ padding: '0.5rem 0.75rem' }}>No matches</div>
              ) : searchResults.map((n, i) => (
                <div
                  key={String(n.id)}
                  onMouseDown={(e) => { e.preventDefault(); focusNode(n.id); setSearch(''); setSearchResultsVisible(false); }}
                  style={{
                    padding: '0.4rem 0.65rem',
                    cursor: 'pointer',
                    background: i === searchHighlightIdx ? 'var(--bg-secondary)' : 'transparent',
                    fontSize: '0.85rem',
                  }}
                >
                  <div>{n.label}</div>
                  {n.ip && <div className="text-muted" style={{ fontSize: '0.75rem' }}>{n.ip}</div>}
                </div>
              ))}
            </div>
          )}
        </div>

        <button className="btn btn-primary btn-sm" onClick={() => setDiscoveryOpen(true)}>Discover Neighbors</button>
        <button className="btn btn-secondary btn-sm" onClick={handleRefresh}>Refresh</button>
        <button className="btn btn-secondary btn-sm" onClick={handleFit}>Fit</button>
        <button className={`btn btn-sm ${pathMode ? 'btn-primary' : 'btn-secondary'}`} onClick={togglePathMode}>{pathMode ? 'Cancel Path' : 'Path Mode'}</button>
        <button className={`btn btn-sm ${searchPanelOpen ? 'btn-primary' : 'btn-secondary'}`} onClick={toggleSearchPanel}>{searchPanelOpen ? 'Close Search' : 'Find MAC/IP/VLAN'}</button>
        <button className={`btn btn-sm ${labelsVisible ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setLabelsVisible((v) => !v)}>Labels</button>
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
        <button className="btn btn-secondary btn-sm" onClick={handleExportPNG}>PNG</button>
        <button className="btn btn-secondary btn-sm" onClick={handleExportSVG}>SVG</button>
        <button className="btn btn-secondary btn-sm" onClick={handleExportJSON}>JSON</button>
      </div>

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

      {pathMode && pathStatus && (
        <div className="card" style={{ padding: '0.5rem 0.85rem', marginBottom: '0.6rem', borderLeft: '3px solid var(--primary)' }}>
          {pathStatus} {' '}
          <button type="button" className="btn btn-sm btn-secondary" onClick={clearPathMode} style={{ marginLeft: '0.6rem' }}>Cancel</button>
        </div>
      )}

      {topologyQuery.isPending && <div className="text-muted">Loading topology…</div>}
      {topologyQuery.error && <div style={{ color: 'var(--danger)' }}>Error: {(topologyQuery.error as Error).message}</div>}

      {data && !data.nodes.length && (
        <div className="card" style={{ padding: '1.5rem', textAlign: 'center' }}>
          <p className="text-muted" style={{ margin: 0 }}>No topology data. Run discovery to populate links.</p>
        </div>
      )}

      <div style={{ position: 'relative', height: 'calc(100vh - 280px)', minHeight: 460, border: '1px solid var(--border)', borderRadius: '0.5rem', overflow: 'hidden', display: data && data.nodes.length ? 'block' : 'none' }}>
        <div ref={containerRef} id="topology-canvas" style={{ width: '100%', height: '100%' }} />
        {searchPanelOpen && (
          <TopologySearchPanel
            onHighlight={stableApplySearchHighlight}
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
            onAddToInventory={(n) => setAddInvTarget(n)}
            onCategoryUpdated={(hostId, newCategory) => {
              if (!data) return;
              const target = data.nodes.find((n) => n.id === hostId);
              if (!target) return;
              const updatedNode = { ...target, device_category: newCategory };
              qc.setQueryData(['topology', groupId ?? null], {
                ...data,
                nodes: data.nodes.map((n) => (n.id === hostId ? updatedNode : n)),
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
        }}
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
