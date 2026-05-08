import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

export type GraphScope = 'device' | 'interface' | string;

export interface GraphTemplateItem {
  id: number;
  label: string;
  metric_name: string;
  line_type: string;
  color: string;
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

export interface GraphTemplateCreatePayload {
  name: string;
  description: string;
  graph_type: string;
  scope: string;
  category: string;
  title_format: string;
  y_axis_label: string;
  stacked: boolean;
  area_fill: boolean;
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

export interface GraphTreeNode {
  id: number;
  title?: string;
  node_type: string;
  sort_order: number;
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

export interface GraphTreeNodePayload {
  title: string;
  node_type: string;
  sort_order: number;
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

export function useCreateGraphTemplate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: GraphTemplateCreatePayload) =>
      apiRequest('/graph-templates', { method: 'POST', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['graph-templates'] }),
  });
}

export function useDeleteGraphTemplate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/graph-templates/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['graph-templates'] }),
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

export function useCreateHostTemplate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: HostTemplatePayload) =>
      apiRequest('/host-templates', { method: 'POST', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['host-templates'] }),
  });
}

export function useUpdateHostTemplate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: HostTemplatePayload }) =>
      apiRequest(`/host-templates/${id}`, { method: 'PUT', body: data }),
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ['host-templates'] });
      qc.invalidateQueries({ queryKey: ['host-template', vars.id] });
    },
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
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ['graph-trees'] });
      qc.invalidateQueries({ queryKey: ['graph-tree', vars.id] });
    },
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
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ['graph-trees'] });
      qc.invalidateQueries({ queryKey: ['graph-tree', vars.treeId] });
    },
  });
}
