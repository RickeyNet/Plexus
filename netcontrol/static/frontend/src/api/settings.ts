import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

// ── Types ──────────────────────────────────────────────────────────────────

export interface FeatureVisibilityEntry {
  key: string;
  label: string;
}

export interface FeatureVisibility {
  catalog: FeatureVisibilityEntry[];
  hidden: string[];
}

export interface AdminCapabilities {
  feature_flags: string[];
  auth_providers: string[];
  feature_visibility: FeatureVisibility;
}

export interface AdminUser {
  id: number;
  username: string;
  display_name: string;
  role: 'admin' | 'user' | string;
  created_at?: string;
  group_ids: number[];
  feature_access: string[];
}

export interface AccessGroup {
  id: number;
  name: string;
  description: string;
  feature_keys: string[];
  member_count?: number;
}

export interface LoginRules {
  max_attempts: number;
  lockout_time: number;
  rate_limit_window: number;
  rate_limit_max: number;
}

export interface RadiusConfig {
  enabled: boolean;
  server: string;
  port: number;
  secret: string;
  timeout: number;
  fallback_to_local: boolean;
  fallback_on_reject: boolean;
  default_group_ids: number[];
}

export interface LdapConfig {
  enabled: boolean;
  server: string;
  port: number;
  use_ssl: boolean;
  bind_dn: string;
  bind_password: string;
  base_dn: string;
  user_search_filter: string;
  user_dn_template?: string;
  group_search_base?: string;
  group_search_filter?: string;
  admin_group_dn: string;
  default_role?: string;
  timeout: number;
  fallback_to_local: boolean;
  fallback_on_reject: boolean;
}

export interface AuthConfig {
  provider: 'local' | 'radius' | 'ldap' | string;
  default_credential_id: number | null;
  job_retention_days: number;
  radius: RadiusConfig;
  ldap: LdapConfig;
}

export interface SyslogConfig {
  enabled: boolean;
  host: string;
  port: number;
  protocol: 'udp' | 'tcp' | string;
  facility: string;
  level: string;
  app_name: string;
  active?: boolean;
}

export interface MonitoringConfig {
  enabled: boolean;
  interval_seconds: number;
  retention_days: number;
  cpu_threshold: number;
  memory_threshold: number;
  collect_routes: boolean;
  collect_vpn: boolean;
  escalation_enabled: boolean;
  escalation_after_minutes: number;
  escalation_check_interval: number;
  default_cooldown_minutes: number;
}

export interface MonitoringPollResult {
  hosts_polled?: number;
  alerts_created?: number;
  errors?: number;
}

export interface TopologyDiscoveryConfig {
  enabled: boolean;
  interval_seconds: number;
}

export interface TopologyDiscoveryResult {
  result?: {
    groups_scanned?: number;
    links_discovered?: number;
    errors?: number;
  };
}

export interface StpDiscoveryConfig {
  enabled: boolean;
  interval_seconds: number;
  all_vlans: boolean;
  vlan_id: number;
  max_vlans: number;
}

export interface StpDiscoveryResult {
  result?: {
    enabled?: boolean;
    groups_scanned?: number;
    ports_collected?: number;
    errors?: number;
  };
}

export interface StpRootPolicy {
  id: number;
  group_id: number;
  group_name?: string;
  vlan_id: number;
  expected_root_bridge_id: string;
  expected_root_hostname?: string;
  enabled: boolean;
}

export interface StpRootPolicyPayload {
  group_id: number;
  vlan_id: number;
  expected_root_bridge_id: string;
  expected_root_hostname: string;
  enabled: boolean;
}

export interface InventoryGroupSummary {
  id: number;
  name: string;
}

export interface CredentialSummary {
  id: number;
  name: string;
  username?: string;
}

// ── Capabilities / users / groups ──────────────────────────────────────────

export function useAdminCapabilities() {
  return useQuery<AdminCapabilities>({
    queryKey: ['admin', 'capabilities'],
    queryFn: () => apiRequest('/admin/capabilities'),
  });
}

export function useAdminUsers() {
  return useQuery<AdminUser[]>({
    queryKey: ['admin', 'users'],
    queryFn: () => apiRequest('/admin/users'),
  });
}

export function useAccessGroups() {
  return useQuery<AccessGroup[]>({
    queryKey: ['admin', 'access-groups'],
    queryFn: () => apiRequest('/admin/access-groups'),
  });
}

export interface AdminUserCreatePayload {
  username: string;
  password: string;
  display_name?: string;
  role: 'admin' | 'user';
  group_ids: number[];
}

export function useCreateAdminUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: AdminUserCreatePayload) =>
      apiRequest<AdminUser>('/admin/users', { method: 'POST', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'users'] }),
  });
}

export interface AdminUserUpdatePayload {
  username?: string;
  display_name?: string;
  role?: 'admin' | 'user';
}

export function useUpdateAdminUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: AdminUserUpdatePayload }) =>
      apiRequest<AdminUser>(`/admin/users/${id}`, { method: 'PUT', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'users'] }),
  });
}

export function useResetAdminUserPassword() {
  return useMutation({
    mutationFn: ({ id, newPassword }: { id: number; newPassword: string }) =>
      apiRequest(`/admin/users/${id}/password`, {
        method: 'PUT',
        body: { new_password: newPassword },
      }),
  });
}

export function useSetAdminUserGroups() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, groupIds }: { id: number; groupIds: number[] }) =>
      apiRequest<AdminUser>(`/admin/users/${id}/groups`, {
        method: 'PUT',
        body: { group_ids: groupIds },
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'users'] }),
  });
}

export function useDeleteAdminUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/admin/users/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'users'] }),
  });
}

export interface AccessGroupPayload {
  name: string;
  description: string;
  feature_keys: string[];
}

export function useCreateAccessGroup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: AccessGroupPayload) =>
      apiRequest<AccessGroup>('/admin/access-groups', { method: 'POST', body: data }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'access-groups'] });
      qc.invalidateQueries({ queryKey: ['admin', 'users'] });
    },
  });
}

export function useUpdateAccessGroup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: AccessGroupPayload }) =>
      apiRequest<AccessGroup>(`/admin/access-groups/${id}`, { method: 'PUT', body: data }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'access-groups'] });
      qc.invalidateQueries({ queryKey: ['admin', 'users'] });
    },
  });
}

export function useDeleteAccessGroup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/admin/access-groups/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'access-groups'] });
      qc.invalidateQueries({ queryKey: ['admin', 'users'] });
    },
  });
}

// ── Login rules ────────────────────────────────────────────────────────────

export function useLoginRules() {
  return useQuery<LoginRules>({
    queryKey: ['admin', 'login-rules'],
    queryFn: () => apiRequest('/admin/login-rules'),
  });
}

export function useUpdateLoginRules() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: LoginRules) =>
      apiRequest<LoginRules>('/admin/login-rules', { method: 'PUT', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'login-rules'] }),
  });
}

// ── Auth config ────────────────────────────────────────────────────────────

export function useAuthConfig() {
  return useQuery<AuthConfig>({
    queryKey: ['admin', 'auth-config'],
    queryFn: () => apiRequest('/admin/auth-config'),
  });
}

export function useUpdateAuthConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: AuthConfig) =>
      apiRequest<AuthConfig>('/admin/auth-config', { method: 'PUT', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'auth-config'] }),
  });
}

// ── Syslog ─────────────────────────────────────────────────────────────────

export function useSyslogConfig() {
  return useQuery<SyslogConfig>({
    queryKey: ['admin', 'syslog-config'],
    queryFn: () => apiRequest('/admin/syslog-config'),
  });
}

export function useUpdateSyslogConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: Omit<SyslogConfig, 'active'>) =>
      apiRequest<SyslogConfig>('/admin/syslog-config', { method: 'PUT', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'syslog-config'] }),
  });
}

export function useTestSyslog() {
  return useMutation({
    mutationFn: () =>
      apiRequest('/admin/syslog-config/test', { method: 'POST' }),
  });
}

// ── Feature visibility ─────────────────────────────────────────────────────

export function useUpdateFeatureVisibility() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (hidden: string[]) =>
      apiRequest<FeatureVisibility>('/admin/feature-visibility', {
        method: 'PUT',
        body: { hidden },
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'capabilities'] }),
  });
}

// ── Topology discovery ─────────────────────────────────────────────────────

export function useTopologyDiscoveryConfig() {
  return useQuery<TopologyDiscoveryConfig>({
    queryKey: ['admin', 'topology-discovery'],
    queryFn: () => apiRequest('/admin/topology-discovery'),
  });
}

export function useUpdateTopologyDiscoveryConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: TopologyDiscoveryConfig) =>
      apiRequest<TopologyDiscoveryConfig>('/admin/topology-discovery', {
        method: 'PUT',
        body: data,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'topology-discovery'] }),
  });
}

export function useRunTopologyDiscovery() {
  return useMutation({
    mutationFn: () =>
      apiRequest<TopologyDiscoveryResult>('/admin/topology-discovery/run-now', {
        method: 'POST',
      }),
  });
}

// ── STP discovery + root policies ──────────────────────────────────────────

export function useStpDiscoveryConfig() {
  return useQuery<StpDiscoveryConfig>({
    queryKey: ['admin', 'topology-stp-discovery'],
    queryFn: () => apiRequest('/admin/topology-stp-discovery'),
  });
}

export function useUpdateStpDiscoveryConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: StpDiscoveryConfig) =>
      apiRequest<StpDiscoveryConfig>('/admin/topology-stp-discovery', {
        method: 'PUT',
        body: data,
      }),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ['admin', 'topology-stp-discovery'] }),
  });
}

export function useRunStpDiscovery() {
  return useMutation({
    mutationFn: () =>
      apiRequest<StpDiscoveryResult>('/admin/topology-stp-discovery/run-now', {
        method: 'POST',
      }),
  });
}

export function useStpRootPolicies() {
  return useQuery<{ policies: StpRootPolicy[] }>({
    queryKey: ['admin', 'topology-stp-root-policies'],
    queryFn: () =>
      apiRequest('/admin/topology-stp-root-policies?limit=2000'),
  });
}

export function useUpsertStpRootPolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: StpRootPolicyPayload) =>
      apiRequest<StpRootPolicy>('/admin/topology-stp-root-policies', {
        method: 'PUT',
        body: data,
      }),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ['admin', 'topology-stp-root-policies'] }),
  });
}

export function useDeleteStpRootPolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (policyId: number) =>
      apiRequest(`/admin/topology-stp-root-policies/${policyId}`, {
        method: 'DELETE',
      }),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ['admin', 'topology-stp-root-policies'] }),
  });
}

// ── Monitoring ─────────────────────────────────────────────────────────────

export function useMonitoringConfig() {
  return useQuery<MonitoringConfig>({
    queryKey: ['admin', 'monitoring'],
    queryFn: () => apiRequest('/admin/monitoring'),
  });
}

export function useUpdateMonitoringConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: MonitoringConfig) =>
      apiRequest<MonitoringConfig>('/admin/monitoring', { method: 'PUT', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'monitoring'] }),
  });
}

export function useRunMonitoringPoll() {
  return useMutation({
    mutationFn: () =>
      apiRequest<MonitoringPollResult>('/admin/monitoring/run-now', {
        method: 'POST',
      }),
  });
}

// ── Helpers reused across tabs ─────────────────────────────────────────────

export function useInventoryGroupsList() {
  return useQuery<InventoryGroupSummary[]>({
    queryKey: ['inventory', 'groups-list'],
    queryFn: () => apiRequest('/inventory'),
  });
}

export function useCredentialsList() {
  return useQuery<CredentialSummary[]>({
    queryKey: ['credentials', 'list'],
    queryFn: () => apiRequest('/credentials'),
  });
}
