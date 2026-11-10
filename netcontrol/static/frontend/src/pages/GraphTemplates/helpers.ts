import type {
  GraphTreeNode,
  GraphTreeNodePayload,
  GraphTreeNodeType,
  HostGraph,
} from '@/api/graphTemplates';
import { descendantIdsOf, treeOrder, type TreeEntry } from '@/lib/tree';

// ── Data series choices ─────────────────────────────────────────────────────

/**
 * Line types the chart builder (`graph_export._build_echart_option`) draws:
 * `bar` becomes a bar series, `area` / `stacked_area` a filled line, and
 * anything else a plain line.
 */
export const LINE_TYPES: readonly { value: string; label: string }[] = [
  { value: 'line', label: 'Line' },
  { value: 'area', label: 'Area' },
  { value: 'stacked_area', label: 'Stacked area' },
  { value: 'bar', label: 'Bar' },
];

/** Consolidation functions the built-in templates use. */
export const CONSOLIDATIONS: readonly { value: string; label: string }[] = [
  { value: 'avg', label: 'Average' },
  { value: 'last', label: 'Last value' },
];

/**
 * Metric names the poller records and the built-in templates plot, offered
 * as suggestions; any other name in the metric store also works.
 */
export const METRIC_SUGGESTIONS: readonly string[] = [
  'cpu_usage',
  'cpu_percent',
  'memory_usage',
  'memory_percent',
  'memory_used_mb',
  'memory_total_mb',
  'uptime',
  'uptime_seconds',
  'ping_rtt',
  'response_time_ms',
  'packet_loss_pct',
  'if_in_octets',
  'if_out_octets',
  'if_in_errors',
  'if_out_errors',
  'if_in_discards',
  'if_out_discards',
  'if_utilization_in',
  'if_utilization_out',
  'if_up_count',
  'if_down_count',
  'route_count',
  'vpn_tunnels_up',
  'vpn_tunnels_down',
];

/**
 * The options for a select, with the current value appended when it is not
 * one of them (a row saved by an older client or the API), so editing the
 * row does not silently change it.
 */
export function withCurrentOption(
  options: readonly { value: string; label: string }[],
  current: string,
): { value: string; label: string }[] {
  if (!current || options.some((o) => o.value === current)) return [...options];
  return [...options, { value: current, label: current }];
}

// ── Host templates ─────────────────────────────────────────────────────────

/** A host template's `device_types` JSON array; empty when missing or malformed. */
export function parseDeviceTypes(raw?: string | null): string[] {
  try {
    const parsed: unknown = JSON.parse(raw || '[]');
    return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === 'string') : [];
  } catch {
    return [];
  }
}

/** The comma-separated device types field as a list, blanks dropped. */
export function splitDeviceTypes(text: string): string[] {
  return text.split(',').map((s) => s.trim()).filter(Boolean);
}

/** The links to add and remove to turn `current` into `desired`. */
export function linkDiff(
  current: Iterable<number>,
  desired: Iterable<number>,
): { toLink: number[]; toUnlink: number[] } {
  const cur = new Set(current);
  const want = new Set(desired);
  return {
    toLink: [...want].filter((id) => !cur.has(id)),
    toUnlink: [...cur].filter((id) => !want.has(id)),
  };
}

// ── Graph trees ────────────────────────────────────────────────────────────

const nodeId = (n: GraphTreeNode) => n.id;
const nodeParent = (n: GraphTreeNode) => n.parent_node_id;
const bySortOrder = (a: GraphTreeNode, b: GraphTreeNode) =>
  (a.sort_order ?? 0) - (b.sort_order ?? 0) || a.id - b.id;

/** Nodes in outline order with their depth, siblings by sort order then id. */
export function orderTreeNodes(nodes: GraphTreeNode[]): TreeEntry<GraphTreeNode>[] {
  return treeOrder(nodes, nodeId, nodeParent, bySortOrder);
}

/** The ids of every node below `id` (children, grandchildren, ...). */
export function nodeDescendantIds(nodes: GraphTreeNode[], id: number): Set<number> {
  return descendantIdsOf(nodes, nodeId, nodeParent, id);
}

/** What a host graph is called in a picker or a tree row. */
export function hostGraphLabel(g: HostGraph): string {
  const base = g.title || g.template_name || `Graph #${g.id}`;
  const inst = g.instance_label || '';
  return inst && !base.includes(inst) ? `${base} (${inst})` : base;
}

export interface NodeFormValues {
  title: string;
  nodeType: GraphTreeNodeType;
  sortOrder: number;
  parentId: number | null;
  hostId: number | null;
  graphId: number | null;
}

export type NodeFormErrors = Partial<Record<'title' | 'host' | 'graph', string>>;

/** Field errors for the node form; empty when it can be saved. */
export function validateNodeForm(v: NodeFormValues, defaultTitle: string): NodeFormErrors {
  const errors: NodeFormErrors = {};
  if (v.nodeType !== 'header' && v.hostId == null) errors.host = 'Choose a host';
  if (v.nodeType === 'graph' && v.graphId == null) errors.graph = 'Choose one of the host’s graphs';
  if (!v.title.trim() && !(v.nodeType !== 'header' && defaultTitle)) errors.title = 'Title is required';
  return errors;
}

/**
 * The create / update body for a node. Host and graph are sent as `null`
 * when the type does not use them, which clears a previous value on update.
 * A blank title on a device or graph node falls back to `defaultTitle`
 * (the host name or graph title).
 */
export function nodePayload(v: NodeFormValues, defaultTitle: string): GraphTreeNodePayload {
  return {
    title: v.title.trim() || (v.nodeType === 'header' ? '' : defaultTitle),
    node_type: v.nodeType,
    sort_order: v.sortOrder,
    parent_node_id: v.parentId,
    host_id: v.nodeType === 'header' ? null : v.hostId,
    graph_id: v.nodeType === 'graph' ? v.graphId : null,
  };
}
