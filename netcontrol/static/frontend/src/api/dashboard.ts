import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

export interface DashboardStats {
  total_hosts?: number;
  total_playbooks?: number;
  total_jobs?: number;
}

export interface DashboardGroup {
  id: number;
  name: string;
}

export interface DashboardMonitoring {
  open_alerts?: number;
}

export interface DeviceHealth {
  host_id?: number;
  hostname?: string;
  ip_address?: string;
  group_id?: number;
  group_name?: string;
  model?: string;
  device_type?: string;
  poll_status?: string;
  cpu_percent?: number | null;
  memory_percent?: number | null;
  packet_loss_pct?: number | null;
  if_up_count?: number | null;
  if_down_count?: number | null;
  response_time_ms?: number | null;
  uptime_seconds?: number | null;
  polled_at?: string | null;
}

export interface DashboardAlert {
  severity?: string;
  hostname?: string;
  message?: string;
  metric?: string;
  created_at?: string;
}

export interface DashboardResponse {
  stats?: DashboardStats;
  recent_jobs?: unknown[];
  groups?: DashboardGroup[];
  monitoring?: DashboardMonitoring;
  device_health?: DeviceHealth[];
  open_alerts?: DashboardAlert[];
}

export function useDashboard() {
  return useQuery<DashboardResponse>({
    queryKey: ['dashboard'],
    queryFn: () => apiRequest('/dashboard'),
  });
}

// ── Custom dashboards ──────────────────────────────────────────────────────

export interface DashboardVariable {
  name: string;
  type: 'group' | 'host';
  default?: string;
}

export interface DashboardPanel {
  id: number;
  dashboard_id: number;
  title: string;
  chart_type: string;
  metric_query_json: string;
  options_json?: string;
  grid_x: number;
  grid_y: number;
  grid_w: number;
  grid_h: number;
}

export interface CustomDashboard {
  id: number;
  name: string;
  description?: string;
  owner?: string;
  variables_json?: string;
  layout_json?: string;
  created_at?: string;
  updated_at?: string;
  panels?: DashboardPanel[];
}

interface DashboardsListResponse {
  dashboards: CustomDashboard[];
}

export function useCustomDashboards() {
  return useQuery<CustomDashboard[]>({
    queryKey: ['custom-dashboards'],
    queryFn: async () => {
      const data = await apiRequest<DashboardsListResponse | CustomDashboard[]>('/dashboards');
      return Array.isArray(data) ? data : (data?.dashboards ?? []);
    },
  });
}

export function useCustomDashboard(id: number | null) {
  return useQuery<CustomDashboard>({
    queryKey: ['custom-dashboard', id],
    queryFn: () => apiRequest(`/dashboards/${id}`),
    enabled: id != null,
  });
}

export interface DashboardCreatePayload {
  name: string;
  description?: string;
  variables_json?: string;
  layout_json?: string;
}

export function useCreateCustomDashboard() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: DashboardCreatePayload) =>
      apiRequest<CustomDashboard>('/dashboards', { method: 'POST', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['custom-dashboards'] }),
  });
}

export function useDeleteCustomDashboard() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => apiRequest(`/dashboards/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['custom-dashboards'] }),
  });
}

export interface PanelPayload {
  title: string;
  chart_type: string;
  metric_query_json: string;
  grid_x?: number;
  grid_y?: number;
  grid_w: number;
  grid_h: number;
  options_json?: string;
}

export function useCreatePanel(dashboardId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: PanelPayload) =>
      apiRequest<DashboardPanel>(`/dashboards/${dashboardId}/panels`, {
        method: 'POST',
        body: data,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['custom-dashboard', dashboardId] }),
  });
}

export function useUpdatePanel(dashboardId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ panelId, data }: { panelId: number; data: Partial<PanelPayload> }) =>
      apiRequest<DashboardPanel>(`/dashboards/${dashboardId}/panels/${panelId}`, {
        method: 'PUT',
        body: data,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['custom-dashboard', dashboardId] }),
  });
}

export function useDeletePanel(dashboardId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (panelId: number) =>
      apiRequest(`/dashboards/${dashboardId}/panels/${panelId}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['custom-dashboard', dashboardId] }),
  });
}

// ── Metrics ────────────────────────────────────────────────────────────────

export interface MetricSample {
  hostname?: string;
  host_id?: number;
  sampled_at?: string;
  period_start?: string;
  val_avg?: number | null;
  value?: number | null;
}

export interface MetricsQueryResponse {
  metric: string;
  step: string;
  range: string;
  count: number;
  data: MetricSample[];
}

export interface MetricsQueryArgs {
  metric: string;
  host?: string;
  range?: string;
  step?: string;
  group?: number | null;
  enabled?: boolean;
}

export function useMetricsQuery({
  metric,
  host = '*',
  range = '6h',
  step = 'auto',
  group = null,
  enabled = true,
}: MetricsQueryArgs) {
  return useQuery<MetricsQueryResponse>({
    queryKey: ['metrics-query', metric, host, range, step, group],
    queryFn: () => {
      const params = new URLSearchParams({ metric, host, range, step });
      if (group != null) params.set('group', String(group));
      return apiRequest(`/metrics/query?${params.toString()}`);
    },
    enabled,
  });
}

// ── Chart annotations ──────────────────────────────────────────────────────
// Mirrors legacy api.js getAnnotations() — deployment/config/alert event
// markers overlaid on custom-dashboard time-series charts.

export interface Annotation {
  timestamp: string;
  category?: string;
  title?: string;
  description?: string;
  user?: string;
}

interface AnnotationsResponse {
  annotations?: Annotation[];
}

// Legacy uses h/d only (app.js rangeToMs); default 24h, same as legacy.
function rangeToMs(range: string): number {
  const m = /^(\d+)([hd])$/.exec(range);
  if (!m) return 86_400_000;
  const units: Record<string, number> = { h: 3_600_000, d: 86_400_000 };
  return parseInt(m[1], 10) * units[m[2]];
}

export interface AnnotationsArgs {
  host?: string;
  range?: string;
  enabled?: boolean;
}

export function useAnnotations({ host = '*', range = '24h', enabled = true }: AnnotationsArgs) {
  return useQuery<Annotation[]>({
    queryKey: ['annotations', host, range],
    queryFn: async () => {
      const end = new Date();
      const start = new Date(end.getTime() - rangeToMs(range));
      const params = new URLSearchParams({
        start: start.toISOString(),
        end: end.toISOString(),
        categories: 'deployment,config,alert',
      });
      // Legacy only sends host_id when a specific host is selected.
      if (host && host !== '*') params.set('host_id', host);
      const res = await apiRequest<AnnotationsResponse>(`/annotations?${params.toString()}`);
      return res?.annotations ?? [];
    },
    enabled,
  });
}

// ── Inventory groups (with optional hosts) ────────────────────────────────

export interface InventoryHostBrief {
  id: number;
  hostname: string;
  ip_address?: string;
}

export interface InventoryGroupWithHosts {
  id: number;
  name: string;
  hosts?: InventoryHostBrief[];
}

interface InventoryListResponse {
  groups?: InventoryGroupWithHosts[];
}

export function useInventoryGroupsForDashboard(includeHosts: boolean) {
  return useQuery<InventoryGroupWithHosts[]>({
    queryKey: ['dashboard-inventory-groups', includeHosts],
    queryFn: async () => {
      const path = includeHosts ? '/inventory?include_hosts=true' : '/inventory';
      const res = await apiRequest<InventoryListResponse | InventoryGroupWithHosts[]>(path);
      return Array.isArray(res) ? res : (res?.groups ?? []);
    },
  });
}
