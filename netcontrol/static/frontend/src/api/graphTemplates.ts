import { useMutation, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

export type GraphScope = 'device' | 'interface' | string;

export interface GraphTemplateItem {
  id: number;
  template_id?: number;
  sort_order: number;
  label: string;
  metric_name: string;
  line_type: string;
  color: string;
  consolidation: string;
  cdef_expression?: string;
  transform?: string;
  legend_format?: string;
}

/** The data series fields the template editor sets. */
export interface GraphTemplateItemPayload {
  sort_order: number;
  metric_name: string;
  label: string;
  color: string;
  line_type: string;
  consolidation: string;
}

export interface GraphTemplate {
  id: number;
  name: string;
  description?: string;
  graph_type: string;
  scope: GraphScope;
  category: string;
  title_format?: string;
  y_axis_label?: string;
  stacked?: boolean;
  area_fill?: boolean;
  grid_w?: number;
  grid_h?: number;
  built_in?: boolean;
  items?: GraphTemplateItem[];
}

export interface GraphTemplatePayload {
  name: string;
  description: string;
  graph_type: string;
  scope: string;
  category: string;
  title_format: string;
  y_axis_label: string;
  stacked: boolean;
  area_fill: boolean;
  grid_w: number;
  grid_h: number;
}

export interface HostTemplateGraphLink {
  id: number;
  name: string;
}

export interface HostTemplate {
  id: number;
  name: string;
  description?: string;
  device_types?: string;
  auto_apply?: boolean;
  graph_templates?: HostTemplateGraphLink[];
}

export interface HostTemplatePayload {
  name: string;
  description: string;
  device_types: string;
  auto_apply: boolean;
}

export type GraphTreeNodeType = 'header' | 'device' | 'graph';

export interface GraphTreeNode {
  id: number;
  tree_id?: number;
  parent_node_id?: number | null;
  title?: string;
  node_type: string;
  sort_order: number;
  host_id?: number | null;
  group_id?: number | null;
  /** A host graph (`/host-graphs`) id, for `graph` nodes. */
  graph_id?: number | null;
}

export interface GraphTree {
  id: number;
  name: string;
  description?: string;
  nodes?: GraphTreeNode[];
}

export interface GraphTreePayload {
  name: string;
  description: string;
}

/**
 * Node fields for create and update. On update an explicit `null` clears
 * the parent / host / graph; a field left out is unchanged.
 */
export interface GraphTreeNodePayload {
  title: string;
  node_type: GraphTreeNodeType;
  sort_order: number;
  parent_node_id: number | null;
  host_id: number | null;
  graph_id: number | null;
}

/** A graph template instantiated on a device (`/host-graphs`). */
export interface HostGraph {
  id: number;
  host_id: number;
  graph_template_id: number;
  title?: string;
  instance_key?: string;
  instance_label?: string;
  template_name?: string;
}

// ── Graph Templates ────────────────────────────────────────────────────────

export function useGraphTemplates() {
  return useQuery<{ graph_templates: GraphTemplate[] }>({
    queryKey: ['graph-templates'],
    queryFn: () => apiRequest('/graph-templates'),
  });
}

export function useGraphTemplate(id: number | null) {
  return useQuery<GraphTemplate>({
    queryKey: ['graph-template', id],
    queryFn: () => apiRequest(`/graph-templates/${id}`),
    enabled: id != null,
  });
}

/** Host template responses embed graph template rows, so they go stale too. */
function invalidateGraphTemplate(qc: QueryClient, id: number) {
  qc.invalidateQueries({ queryKey: ['graph-templates'] });
  qc.invalidateQueries({ queryKey: ['graph-template', id] });
  qc.invalidateQueries({ queryKey: ['host-templates'] });
  qc.invalidateQueries({ queryKey: ['host-template'] });
}

export function useCreateGraphTemplate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: GraphTemplatePayload) =>
      apiRequest<GraphTemplate>('/graph-templates', { method: 'POST', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['graph-templates'] }),
  });
}

export function useUpdateGraphTemplate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: Partial<GraphTemplatePayload> }) =>
      apiRequest<GraphTemplate>(`/graph-templates/${id}`, { method: 'PUT', body: data }),
    onSuccess: (_, vars) => invalidateGraphTemplate(qc, vars.id),
  });
}

export function useDeleteGraphTemplate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/graph-templates/${id}`, { method: 'DELETE' }),
    onSuccess: (_, id) => {
      // Drop the deleted row's detail rather than refetching it into a 404.
      qc.removeQueries({ queryKey: ['graph-template', id] });
      invalidateGraphTemplate(qc, id);
    },
  });
}

// ── Graph Template Items (data series) ─────────────────────────────────────

interface ItemVars {
  templateId: number;
  itemId: number;
}

export function useCreateGraphTemplateItem() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ templateId, data }: { templateId: number; data: GraphTemplateItemPayload }) =>
      apiRequest<GraphTemplateItem>(`/graph-templates/${templateId}/items`, { method: 'POST', body: data }),
    onSuccess: (_, vars) => qc.invalidateQueries({ queryKey: ['graph-template', vars.templateId] }),
  });
}

export function useUpdateGraphTemplateItem() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ templateId, itemId, data }: ItemVars & { data: Partial<GraphTemplateItemPayload> }) =>
      apiRequest<GraphTemplateItem>(`/graph-templates/${templateId}/items/${itemId}`, { method: 'PUT', body: data }),
    onSuccess: (_, vars) => qc.invalidateQueries({ queryKey: ['graph-template', vars.templateId] }),
  });
}

export function useDeleteGraphTemplateItem() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ templateId, itemId }: ItemVars) =>
      apiRequest(`/graph-templates/${templateId}/items/${itemId}`, { method: 'DELETE' }),
    onSuccess: (_, vars) => qc.invalidateQueries({ queryKey: ['graph-template', vars.templateId] }),
  });
}

// ── Host Templates ─────────────────────────────────────────────────────────

export function useHostTemplates() {
  return useQuery<{ host_templates: HostTemplate[] }>({
    queryKey: ['host-templates'],
    queryFn: () => apiRequest('/host-templates'),
  });
}

export function useHostTemplate(id: number | null) {
  return useQuery<HostTemplate>({
    queryKey: ['host-template', id],
    queryFn: () => apiRequest(`/host-templates/${id}`),
    enabled: id != null,
  });
}

function invalidateHostTemplate(qc: QueryClient, id: number) {
  qc.invalidateQueries({ queryKey: ['host-templates'] });
  qc.invalidateQueries({ queryKey: ['host-template', id] });
}

export function useCreateHostTemplate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: HostTemplatePayload) =>
      apiRequest<HostTemplate>('/host-templates', { method: 'POST', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['host-templates'] }),
  });
}

export function useUpdateHostTemplate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: HostTemplatePayload }) =>
      apiRequest(`/host-templates/${id}`, { method: 'PUT', body: data }),
    onSuccess: (_, vars) => invalidateHostTemplate(qc, vars.id),
  });
}

export function useDeleteHostTemplate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/host-templates/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['host-templates'] }),
  });
}

interface HostTemplateLinkVars {
  hostTemplateId: number;
  graphTemplateId: number;
}

/** Assign a graph template to a host template (idempotent). */
export function useLinkHostTemplateGraph() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ hostTemplateId, graphTemplateId }: HostTemplateLinkVars) =>
      apiRequest(`/host-templates/${hostTemplateId}/graph-templates/${graphTemplateId}`, { method: 'POST' }),
    onSettled: (_data, _err, vars) => invalidateHostTemplate(qc, vars.hostTemplateId),
  });
}

/** Remove a graph template from a host template. */
export function useUnlinkHostTemplateGraph() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ hostTemplateId, graphTemplateId }: HostTemplateLinkVars) =>
      apiRequest(`/host-templates/${hostTemplateId}/graph-templates/${graphTemplateId}`, { method: 'DELETE' }),
    onSettled: (_data, _err, vars) => invalidateHostTemplate(qc, vars.hostTemplateId),
  });
}

// ── Host Graphs ────────────────────────────────────────────────────────────

/** The graphs instantiated on one host; idle until a host is chosen. */
export function useHostGraphs(hostId: number | null) {
  return useQuery<{ host_graphs: HostGraph[] }>({
    queryKey: ['host-graphs', hostId],
    queryFn: () => apiRequest(`/host-graphs?host_id=${hostId}`),
    enabled: hostId != null,
  });
}

// ── Graph Trees ────────────────────────────────────────────────────────────

export function useGraphTrees() {
  return useQuery<{ graph_trees: GraphTree[] }>({
    queryKey: ['graph-trees'],
    queryFn: () => apiRequest('/graph-trees'),
  });
}

export function useGraphTree(id: number | null) {
  return useQuery<GraphTree>({
    queryKey: ['graph-tree', id],
    queryFn: () => apiRequest(`/graph-trees/${id}`),
    enabled: id != null,
  });
}

function invalidateGraphTree(qc: QueryClient, treeId: number) {
  qc.invalidateQueries({ queryKey: ['graph-trees'] });
  qc.invalidateQueries({ queryKey: ['graph-tree', treeId] });
}

export function useCreateGraphTree() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: GraphTreePayload) =>
      apiRequest('/graph-trees', { method: 'POST', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['graph-trees'] }),
  });
}

export function useUpdateGraphTree() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: GraphTreePayload }) =>
      apiRequest(`/graph-trees/${id}`, { method: 'PUT', body: data }),
    onSuccess: (_, vars) => invalidateGraphTree(qc, vars.id),
  });
}

export function useDeleteGraphTree() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/graph-trees/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['graph-trees'] }),
  });
}

export function useCreateGraphTreeNode() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ treeId, data }: { treeId: number; data: GraphTreeNodePayload }) =>
      apiRequest(`/graph-trees/${treeId}/nodes`, { method: 'POST', body: data }),
    onSuccess: (_, vars) => invalidateGraphTree(qc, vars.treeId),
  });
}

export function useUpdateGraphTreeNode() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ treeId, nodeId, data }: { treeId: number; nodeId: number; data: Partial<GraphTreeNodePayload> }) =>
      apiRequest(`/graph-trees/${treeId}/nodes/${nodeId}`, { method: 'PUT', body: data }),
    onSuccess: (_, vars) => invalidateGraphTree(qc, vars.treeId),
  });
}

/** Deletes the node and, by cascade, every node below it. */
export function useDeleteGraphTreeNode() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ treeId, nodeId }: { treeId: number; nodeId: number }) =>
      apiRequest(`/graph-trees/${treeId}/nodes/${nodeId}`, { method: 'DELETE' }),
    onSuccess: (_, vars) => invalidateGraphTree(qc, vars.treeId),
  });
}
