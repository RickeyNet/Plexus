import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import type { ExternalReferenceBody, ReferencedRow } from '@/lib/secretsProviders';

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
  session_never_expires?: boolean;
  /** Switched off by an admin: no sign-in, sessions and AI-access tokens refused. */
  disabled?: boolean;
  /** Limited to selected inventory groups by its access groups. */
  object_scope_restricted?: boolean;
}

/** ``all``: every device. ``groups``: only the granted inventory groups
 * (each with its sub-groups). */
export type ObjectScope = 'all' | 'groups';

export interface InventoryScopeGrant {
  inventory_group_id: number;
  can_write: boolean;
}

export interface AccessGroup {
  id: number;
  name: string;
  description: string;
  feature_keys: string[];
  member_count?: number;
  object_scope?: ObjectScope;
  inventory_scopes?: InventoryScopeGrant[];
}

export interface LoginRules {
  max_attempts: number;
  lockout_time: number;
  rate_limit_window: number;
  rate_limit_max: number;
  // 0 disables idle-timeout enforcement globally; otherwise capped at 86400 (24h).
  session_idle_timeout: number;
}

export interface RadiusConfig {
  enabled: boolean;
  server: string;
  port: number;
  secret: string;
  timeout: number;
  // Blast-RADIUS (CVE-2024-3596) mitigation, on for a new install; requires
  // a server that echoes Message-Authenticator in replies.
  enforce_message_authenticator: boolean;
  fallback_to_local: boolean;
  fallback_on_reject: boolean;
  default_group_ids: number[];
}

export interface TacacsConfig {
  enabled: boolean;
  server: string;
  port: number;
  secret: string;
  timeout: number;
  // ascii = interactive login flow (IOS default); pap = password in START.
  authen_type: 'ascii' | 'pap' | string;
  // Send an exec authorization (service=shell cmd=) after PASS and map the
  // reply's AV pairs onto a Plexus role. Off = authenticate only.
  authorize: boolean;
  service: string;
  // AV pair whose value (admin|user) sets the role; add it as a custom
  // attribute on the ISE TACACS profile.
  role_attribute: string;
  // priv-lvl >= this maps to admin; 0 disables the rule.
  admin_priv_lvl: number;
  default_role?: string;
  fallback_to_local: boolean;
  fallback_on_reject: boolean;
  default_group_ids: number[];
}

export interface LdapConfig {
  enabled: boolean;
  server: string;
  port: number;
  use_ssl: boolean;
  // STARTTLS on the plaintext port; ignored when use_ssl is set.
  use_starttls: boolean;
  /** Accept a connection without SSL or STARTTLS; the server refuses the
   * save without it and clears it while either is on. */
  allow_cleartext?: boolean;
  // OpenLDAP certificate policy for ldaps/STARTTLS connections.
  tls_verify: 'never' | 'allow' | 'try' | 'demand' | 'hard' | string;
  // CA bundle path on the Plexus host; empty = system trust store.
  ca_cert_file: string;
  bind_dn: string;
  bind_password: string;
  base_dn: string;
  user_search_filter: string;
  /** The entry attribute that names the account; empty = the name as typed. */
  username_attribute?: string;
  user_dn_template?: string;
  group_search_base?: string;
  group_search_filter?: string;
  admin_group_dn: string;
  default_role?: string;
  timeout: number;
  fallback_to_local: boolean;
  fallback_on_reject: boolean;
  default_group_ids: number[];
}

export interface OidcGroupMapping {
  group: string;
  access_group_id: number;
}

// OpenID Connect single sign-on: an extra sign-in method next to the
// password form (docs/sso-oidc.md).
export interface OidcConfig {
  enabled: boolean;
  issuer: string;
  client_id: string;
  // Write-only: shown masked; sending the mask back keeps the saved secret,
  // empty = public client.
  client_secret: string;
  token_auth_method: 'client_secret_basic' | 'client_secret_post' | string;
  scopes: string;
  username_claim: string;
  /** Only read when the username claim is `email`: accept a token without
   * the `email_verified` claim. */
  allow_unverified_email?: boolean;
  display_name_claim: string;
  groups_claim: string;
  admin_groups: string[];
  default_role: string;
  default_group_ids: number[];
  sync_groups: boolean;
  group_mappings: OidcGroupMapping[];
  button_label: string;
  primary: boolean;
  // Sign-in uses only this stored value; a save with it empty stores the
  // callback path on the address the admin is using.
  redirect_uri: string;
  ca_cert_file: string;
}

// SAML 2.0 single sign-on, next to OIDC (docs/sso-saml.md). The role and
// access group keys mean what they mean for OIDC.
export interface SamlConfig {
  enabled: boolean;
  idp_entity_id: string;
  /** HTTP-Redirect SingleSignOnService location. */
  idp_sso_url: string;
  /** PEM signing certificates (several during a rollover). */
  idp_certs: string[];
  idp_metadata_url: string;
  /** Sent empty = the server fills it (and `acs_url`) from the address of
   * the saving request and stores it. */
  sp_entity_id: string;
  acs_url: string;
  ca_cert_file: string;
  /** Empty = the email attribute, else the NameID. */
  username_attribute: string;
  email_attribute: string;
  display_name_attribute: string;
  groups_attribute: string;
  /** The attribute the account is bound to; empty = the NameID. */
  subject_attribute?: string;
  /** AuthnContextClassRef values, one of which the IdP must assert. */
  required_authn_context?: string[];
  admin_groups: string[];
  default_role: string;
  default_group_ids: number[];
  sync_groups: boolean;
  group_mappings: OidcGroupMapping[];
  button_label: string;
  primary: boolean;
}

export interface SamlCertSummary {
  fingerprint: string;
  not_after: string;
}

export interface SamlSpInfo {
  sp_entity_id: string;
  acs_url: string;
  metadata_url: string;
  certs: SamlCertSummary[];
  /** False while the SP entity ID or ACS URL is not stored yet: the values
   * above are what saving the settings stores. Missing on older servers. */
  configured?: boolean;
}

export interface SamlMetadataImport {
  ok: boolean;
  idp_entity_id: string;
  idp_sso_url: string;
  idp_certs: string[];
  certs: SamlCertSummary[];
  error: string;
}

export interface OidcTestResult {
  ok: boolean;
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  algorithms: string[];
  key_count: number;
  redirect_uri: string;
  /** False while no redirect URI is stored: the value above is what saving
   * the settings stores. Missing on older servers. */
  configured?: boolean;
  error: string;
}

export interface AuthConfig {
  provider: 'local' | 'radius' | 'tacacs' | 'ldap' | string;
  default_credential_id: number | null;
  service_credential_id: number | null;
  job_retention_days: number;
  /** Days the per-object change log keeps a change (1-3650). */
  change_log_retention_days: number;
  radius: RadiusConfig;
  tacacs: TacacsConfig;
  ldap: LdapConfig;
  oidc: OidcConfig;
  /** Missing on servers without SAML support. */
  saml?: SamlConfig;
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

export interface FlowCollectorConfig {
  enabled: boolean;
  netflow_port: number;
  // 0 disables the sFlow listener.
  sflow_port: number;
  retention_hours: number;
  summary_retention_days: number;
  aggregation_interval_seconds: number;
  netflow_running?: boolean;
  sflow_running?: boolean;
}

/** Saved settings of the inbound syslog and SNMP trap receivers. */
export interface EventReceiverSettings {
  syslog_enabled: boolean;
  syslog_port: number;
  trap_enabled: boolean;
  trap_port: number;
  syslog_alerts: boolean;
  config_change_trigger: boolean;
  repoll_trigger: boolean;
  recollect_trigger: boolean;
  /** Sum OPNsense firewall log (filterlog) lines per rule; off drops them. */
  filterlog_evidence: boolean;
  /** Syslog over TCP (RFC 6587). */
  syslog_tcp_enabled: boolean;
  syslog_tcp_port: number;
  /** Syslog over TLS (RFC 5425); needs a stored server certificate. */
  syslog_tls_enabled: boolean;
  syslog_tls_port: number;
  /** Mutual TLS: only devices with a certificate the stored client CA signed may connect. */
  syslog_tls_require_client_cert: boolean;
  /**
   * With client certificates required: the certificate must also name the
   * inventory host at the source address (SAN IP address, or SAN DNS name or
   * common name equal to its hostname).
   */
  syslog_tls_match_client_cert: boolean;
  /** Off: syslog over UDP is stored but raises no alert and starts no trigger. */
  syslog_udp_actions: boolean;
  /** Raise alerts from the SNMP trap rules (re-poll and backup follow the two triggers above). */
  trap_alerts: boolean;
}

/** The syslog stream listeners: TCP and TLS. */
export type SyslogStreamKind = 'syslog_tcp' | 'syslog_tls';

/**
 * The settings plus live listener state and counters since each receiver
 * started. The `syslog_*` keys describe the UDP listener only.
 */
export interface EventReceiverConfig extends EventReceiverSettings {
  syslog_running?: boolean;
  trap_running?: boolean;
  syslog_tcp_running?: boolean;
  syslog_tls_running?: boolean;
  syslog_listening_port?: number | null;
  trap_listening_port?: number | null;
  syslog_tcp_listening_port?: number | null;
  syslog_tls_listening_port?: number | null;
  syslog_received?: number;
  trap_received?: number;
  syslog_tcp_received?: number;
  syslog_tls_received?: number;
  syslog_errors?: number;
  trap_errors?: number;
  /** Traps from inventory hosts dropped since Plexus started: a wrong v1 / v2c community, an SNMPv3 trap failing its USM checks. */
  trap_dropped_community?: number;
  trap_dropped_v3?: number;
  /** Stream listeners: unreadable messages, framing errors and failed TLS handshakes. */
  syslog_tcp_errors?: number;
  syslog_tls_errors?: number;
  /** ISO timestamps; '' when none yet. */
  syslog_last_message_at?: string;
  trap_last_message_at?: string;
  syslog_tcp_last_message_at?: string;
  syslog_tls_last_message_at?: string;
  syslog_started_at?: string;
  trap_started_at?: string;
  syslog_tcp_started_at?: string;
  syslog_tls_started_at?: string;
  /** Connections open now, and connections closed at once over a limit or by the source allowlist. */
  syslog_tcp_connections?: number;
  syslog_tls_connections?: number;
  syslog_tcp_connections_refused?: number;
  syslog_tls_connections_refused?: number;
  /** TLS connections closed after the handshake because the client certificate did not name the host. */
  syslog_tls_connections_cert_refused?: number;
  /** Why an enabled stream listener is not running; '' when fine. */
  syslog_tcp_error?: string;
  syslog_tls_error?: string;
  /** Events dropped on buffer overflow since Plexus started (both receivers). */
  events_dropped?: number;
  events_pending?: number;
  /** OPNsense filterlog lines counted into the rule evidence since Plexus started. */
  filterlog_received?: number;
  /** Filterlog lines dropped (switch off, unknown source, memory bound) since Plexus started. */
  filterlog_dropped?: number;
  filterlog_unknown_source?: number;
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

/** `ext_*`: the external secrets provider reference of the credential, if
 *  any (docs/secrets-providers.md). */
export interface CredentialSummary extends ReferencedRow {
  id: number;
  name: string;
  username?: string;
}

// ── Capabilities / users / groups ──────────────────────────────────────────

export function useAdminCapabilities() {
  return useQuery<AdminCapabilities>({
    queryKey: ['admin', 'capabilities'],
    queryFn: ({ signal }) => apiRequest('/admin/capabilities', { signal }),
  });
}

export function useAdminUsers() {
  return useQuery<AdminUser[]>({
    queryKey: ['admin', 'users'],
    queryFn: ({ signal }) => apiRequest('/admin/users', { signal }),
  });
}

/** `enabled` false skips the request (the list is admin only). */
export function useAccessGroups(enabled = true) {
  return useQuery<AccessGroup[]>({
    queryKey: ['admin', 'access-groups'],
    queryFn: ({ signal }) => apiRequest('/admin/access-groups', { signal }),
    enabled,
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
  session_never_expires?: boolean;
  disabled?: boolean;
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
  object_scope?: ObjectScope;
  inventory_scopes?: InventoryScopeGrant[];
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
    queryFn: ({ signal }) => apiRequest('/admin/login-rules', { signal }),
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
    queryFn: ({ signal }) => apiRequest('/admin/auth-config', { signal }),
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

/** Fetch the provider's discovery document and keys. Fields left out fall
 * back to the saved settings on the server. */
export function testOidcConnection(body: { issuer?: string; ca_cert_file?: string } = {}) {
  return apiRequest<OidcTestResult>('/admin/auth-config/oidc/test', { method: 'POST', body });
}

export function useTestOidcConnection() {
  return useMutation({ mutationFn: testOidcConnection });
}

/** What to register at the SAML IdP, and the saved certificates. */
export function useSamlSpInfo() {
  return useQuery<SamlSpInfo>({
    queryKey: ['admin', 'auth-config', 'saml-sp'],
    queryFn: ({ signal }) => apiRequest('/admin/auth-config/saml/sp', { signal }),
  });
}

/** Read IdP metadata (pasted XML, else fetched from the URL). Nothing is
 * saved; the form fills itself from the answer. */
export function importSamlMetadata(body: { xml?: string; url?: string; entity_id?: string; ca_cert_file?: string }) {
  return apiRequest<SamlMetadataImport>('/admin/auth-config/saml/metadata', { method: 'POST', body });
}

export function useImportSamlMetadata() {
  return useMutation({ mutationFn: importSamlMetadata });
}

// ── Syslog ─────────────────────────────────────────────────────────────────

export function useSyslogConfig() {
  return useQuery<SyslogConfig>({
    queryKey: ['admin', 'syslog-config'],
    queryFn: ({ signal }) => apiRequest('/admin/syslog-config', { signal }),
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

// ── SIEM audit-event forwarding ────────────────────────────────────────────

export interface SiemSink {
  id: string;
  name: string;
  enabled: boolean;
  protocol: 'udp' | 'tcp' | 'tls' | 'https' | string;
  format: 'cef' | 'json' | string;
  host: string;
  port: number;
  url: string;
  bearer_token: string;
  tls_verify: boolean;
  tls_ca_pem: string;
  tls_client_cert_pem: string;
  tls_client_key_pem: string;
  severity_floor: string;
  queue_size: number;
  max_retries: number;
  backoff_base: number;
  backoff_cap: number;
}

export interface SiemSinkStats {
  id: string;
  name: string;
  enabled: boolean;
  protocol: string;
  queue_depth: number;
  queue_size: number;
  delivered: number;
  delivery_failures: number;
  dropped_queue_full: number;
  dropped_below_severity: number;
  last_error: string;
  last_delivery_at: string;
  last_failure_at: string;
}

export interface SiemSinksResponse {
  sinks: SiemSink[];
  stats: SiemSinkStats[];
}

export function useSiemSinks() {
  return useQuery<SiemSinksResponse>({
    queryKey: ['admin', 'siem-sinks'],
    queryFn: ({ signal }) => apiRequest('/admin/siem-sinks', { signal }),
    // Only polls while the SIEM settings tab is mounted. 15s keeps delivery
    // stats reasonably live for an admin watching a queue drain without
    // hammering the endpoint.
    refetchInterval: 15_000,
  });
}

export function useCreateSiemSink() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: Partial<SiemSink>) =>
      apiRequest<SiemSink>('/admin/siem-sinks', { method: 'POST', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'siem-sinks'] }),
  });
}

export function useUpdateSiemSink() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<SiemSink> }) =>
      apiRequest<SiemSink>(`/admin/siem-sinks/${encodeURIComponent(id)}`, {
        method: 'PUT',
        body: data,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'siem-sinks'] }),
  });
}

export function useDeleteSiemSink() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      apiRequest<{ ok: boolean }>(`/admin/siem-sinks/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'siem-sinks'] }),
  });
}

export function useTestSiemSink() {
  return useMutation({
    mutationFn: (id: string) =>
      apiRequest<{ ok: boolean; error: string }>(
        `/admin/siem-sinks/${encodeURIComponent(id)}/test`,
        { method: 'POST' },
      ),
  });
}

// ── Alert notification channels ─────────────────────────────────────────────

export type NotificationChannelType = 'email' | 'pagerduty' | 'webhook' | 'teams' | 'slack' | 'webex';

export interface NotificationChannel {
  id: string;
  name: string;
  enabled: boolean;
  type: NotificationChannelType | string;
  severity_floor: string;
  queue_size: number;
  max_retries: number;
  backoff_base: number;
  backoff_cap: number;
  // email
  smtp_host: string;
  smtp_port: number;
  smtp_use_tls: boolean;
  smtp_use_ssl: boolean;
  smtp_username: string;
  smtp_password: string;
  mail_from: string;
  mail_to: string;
  // pagerduty
  routing_key: string;
  // webhook
  webhook_url: string;
  webhook_auth_header: string;
  webhook_auth_value: string;
  verify_tls: boolean;
  // teams
  teams_webhook_url: string;
  // slack / webex: channel or room id the ChatOps bot posts to
  chat_channel?: string;
}

export interface NotificationChannelStats {
  id: string;
  name: string;
  enabled: boolean;
  type: string;
  queue_depth: number;
  queue_size: number;
  delivered: number;
  delivery_failures: number;
  dropped_queue_full: number;
  dropped_below_severity: number;
  last_error: string;
  last_delivery_at: string;
  last_failure_at: string;
}

export interface NotificationChannelsResponse {
  channels: NotificationChannel[];
  default_channel_ids: string[];
  stats: NotificationChannelStats[];
}

/**
 * Admin-only. `live` (the default) refetches every 15 s for the delivery
 * stats; a caller that only needs the channel list passes false.
 */
export function useNotificationChannels(enabled = true, live = true) {
  return useQuery<NotificationChannelsResponse>({
    queryKey: ['admin', 'notification-channels'],
    queryFn: ({ signal }) => apiRequest('/admin/notification-channels', { signal }),
    // Keep delivery stats reasonably live while the tab is mounted.
    refetchInterval: live ? 15_000 : false,
    enabled,
  });
}

export function useCreateNotificationChannel() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: Partial<NotificationChannel>) =>
      apiRequest<NotificationChannel>('/admin/notification-channels', {
        method: 'POST',
        body: data,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'notification-channels'] }),
  });
}

export function useUpdateNotificationChannel() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<NotificationChannel> }) =>
      apiRequest<NotificationChannel>(
        `/admin/notification-channels/${encodeURIComponent(id)}`,
        { method: 'PUT', body: data },
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'notification-channels'] }),
  });
}

export function useDeleteNotificationChannel() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      apiRequest<{ ok: boolean }>(
        `/admin/notification-channels/${encodeURIComponent(id)}`,
        { method: 'DELETE' },
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'notification-channels'] }),
  });
}

export function useTestNotificationChannel() {
  return useMutation({
    mutationFn: (id: string) =>
      apiRequest<{ ok: boolean; error: string }>(
        `/admin/notification-channels/${encodeURIComponent(id)}/test`,
        { method: 'POST' },
      ),
  });
}

export function useSetNotificationDefaults() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (default_channel_ids: string[]) =>
      apiRequest<{ default_channel_ids: string[] }>(
        '/admin/notification-channels-defaults',
        { method: 'PUT', body: { default_channel_ids } },
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'notification-channels'] }),
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
    queryFn: ({ signal }) => apiRequest('/admin/topology-discovery', { signal }),
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
    queryFn: ({ signal }) => apiRequest('/admin/topology-stp-discovery', { signal }),
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
    queryFn: ({ signal }) =>
      apiRequest('/admin/topology-stp-root-policies?limit=2000', { signal }),
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
    queryFn: ({ signal }) => apiRequest('/admin/monitoring', { signal }),
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

// ── NetFlow / sFlow collector ──────────────────────────────────────────────

export function useFlowCollectorConfig() {
  return useQuery<FlowCollectorConfig>({
    queryKey: ['admin', 'flows', 'config'],
    queryFn: ({ signal }) => apiRequest('/admin/flows/config', { signal }),
  });
}

export function useUpdateFlowCollectorConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: FlowCollectorConfig) =>
      apiRequest<FlowCollectorConfig>('/admin/flows/config', {
        method: 'PUT',
        body: data,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'flows', 'config'] }),
  });
}

// ── Syslog / SNMP trap receivers ───────────────────────────────────────────

export function useEventReceiverConfig() {
  return useQuery<EventReceiverConfig>({
    queryKey: ['admin', 'event-receivers', 'config'],
    queryFn: ({ signal }) => apiRequest('/admin/metrics/receivers/config', { signal }),
    // Keeps the running state and counters current while the tab is open.
    refetchInterval: 15_000,
  });
}

export function useUpdateEventReceiverConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: EventReceiverSettings) =>
      apiRequest<EventReceiverConfig>('/admin/metrics/receivers/config', {
        method: 'PUT',
        body: data,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'event-receivers', 'config'] }),
  });
}

/** The stored syslog TLS server certificate (parsed). */
export interface SyslogTlsCertificate {
  subject: string;
  issuer: string;
  /** ISO timestamps. */
  not_before: string;
  not_after: string;
  /** Colon separated hex. */
  sha256_fingerprint: string;
  sans: string[];
  self_signed: boolean;
}

/** The syslog TLS certificate and client CA. The private key is never returned. */
export interface SyslogTlsState {
  has_certificate: boolean;
  certificate: SyslogTlsCertificate | null;
  cert_pem: string;
  has_client_ca: boolean;
  client_ca: { subject: string; not_after: string }[];
  client_ca_pem: string;
}

/**
 * `cert_pem` and `key_pem` go together (both left out keeps the stored
 * certificate); `client_ca_pem` is independent and '' removes the client CA.
 */
export interface SyslogTlsUpload {
  cert_pem?: string;
  key_pem?: string;
  client_ca_pem?: string;
}

export interface SyslogTlsGenerate {
  common_name: string;
  /** DNS names or IP addresses, at most 32. */
  sans: string[];
  /** 1 to 3650. */
  days: number;
}

const SYSLOG_TLS_PATH = '/admin/metrics/receivers/tls';
const SYSLOG_TLS_KEY = ['admin', 'event-receivers', 'tls'];

export function useSyslogTls() {
  return useQuery<SyslogTlsState>({
    queryKey: SYSLOG_TLS_KEY,
    queryFn: ({ signal }) => apiRequest(SYSLOG_TLS_PATH, { signal }),
  });
}

/**
 * A certificate change restarts a running TLS listener, so the receiver
 * config (its running state and error) is refetched along with the TLS state.
 */
function useSyslogTlsMutation<V>(request: (vars: V) => Promise<SyslogTlsState>) {
  const qc = useQueryClient();
  return useMutation<SyslogTlsState, Error, V>({
    mutationFn: request,
    onSuccess: (saved) => {
      qc.setQueryData(SYSLOG_TLS_KEY, saved);
      void qc.invalidateQueries({ queryKey: ['admin', 'event-receivers', 'config'] });
      return qc.invalidateQueries({ queryKey: SYSLOG_TLS_KEY });
    },
  });
}

export function useSaveSyslogTls() {
  return useSyslogTlsMutation((data: SyslogTlsUpload) =>
    apiRequest<SyslogTlsState>(SYSLOG_TLS_PATH, { method: 'PUT', body: data }),
  );
}

export function useGenerateSyslogTls() {
  return useSyslogTlsMutation((data: SyslogTlsGenerate) =>
    apiRequest<SyslogTlsState>(`${SYSLOG_TLS_PATH}/generate`, { method: 'POST', body: data }),
  );
}

export function useDeleteSyslogTls() {
  return useSyslogTlsMutation<void>(() => apiRequest<SyslogTlsState>(SYSLOG_TLS_PATH, { method: 'DELETE' }));
}

// ── AI access (MCP endpoint and tokens) ────────────────────────────────────

export interface McpSettings {
  enabled: boolean;
  max_result_bytes: number;
  max_rows: number;
  calls_per_minute: number;
}

export interface McpTokenRecord {
  id: number;
  name: string;
  /** First characters of the token, for telling tokens apart. */
  token_prefix: string;
  owner_user_id: number;
  owner_username: string;
  owner_role: string;
  categories: string[];
  /** '' (never) or YYYY-MM-DD. */
  expires_at: string;
  created_at: string;
  created_by: string;
  last_used_at: string;
  call_count: number;
  /** '' while the token is usable. */
  revoked_at: string;
}

export interface McpTokenList {
  tokens: McpTokenRecord[];
  categories: string[];
}

export interface McpTokenCreatePayload {
  name: string;
  owner_user_id: number;
  categories: string[];
  expires_at: string;
}

export interface McpTokenCreated {
  /** The token itself. Returned once, never again. */
  token: string;
  record: McpTokenRecord;
}

export function useMcpSettings() {
  return useQuery<McpSettings>({
    queryKey: ['admin', 'mcp', 'settings'],
    queryFn: ({ signal }) => apiRequest('/admin/mcp/settings', { signal }),
  });
}

export function useUpdateMcpSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: Partial<McpSettings>) =>
      apiRequest<McpSettings>('/admin/mcp/settings', { method: 'PUT', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'mcp', 'settings'] }),
  });
}

export function useMcpTokens() {
  return useQuery<McpTokenList>({
    queryKey: ['admin', 'mcp', 'tokens'],
    queryFn: ({ signal }) => apiRequest('/admin/mcp/tokens', { signal }),
  });
}

export function useCreateMcpToken() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: McpTokenCreatePayload) =>
      apiRequest<McpTokenCreated>('/admin/mcp/tokens', { method: 'POST', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'mcp', 'tokens'] }),
  });
}

export function useRevokeMcpToken() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => apiRequest(`/admin/mcp/tokens/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'mcp', 'tokens'] }),
  });
}

// ── Helpers reused across tabs ─────────────────────────────────────────────

export function useInventoryGroupsList() {
  return useQuery<InventoryGroupSummary[]>({
    queryKey: ['inventory', 'groups-list'],
    queryFn: ({ signal }) => apiRequest('/inventory', { signal }),
  });
}

export function useCredentialsList() {
  return useQuery<CredentialSummary[]>({
    queryKey: ['credentials', 'list'],
    queryFn: ({ signal }) => apiRequest('/credentials', { signal }),
  });
}

// ── Service credentials (admin-only) ───────────────────────────────────────

export interface ServiceCredentialPayload {
  name: string;
  username: string;
  password: string;
  secret?: string;
  external?: ExternalReferenceBody;
}

export interface ServiceCredentialUpdatePayload {
  name?: string;
  username?: string;
  password?: string;
  secret?: string;
  external?: ExternalReferenceBody;
}

export function useServiceCredentialsList(enabled = true) {
  return useQuery<CredentialSummary[]>({
    queryKey: ['credentials', 'service'],
    queryFn: ({ signal }) => apiRequest('/credentials/service', { signal }),
    // The endpoint is admin-only; non-admin callers pass enabled=false so
    // the query never fires (and never retries a guaranteed 403).
    enabled,
  });
}

export function useCreateServiceCredential() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: ServiceCredentialPayload) =>
      apiRequest<{ id: number }>('/credentials/service', {
        method: 'POST',
        body: data,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['credentials', 'service'] }),
  });
}

export function useUpdateServiceCredential() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: ServiceCredentialUpdatePayload }) =>
      apiRequest(`/credentials/service/${id}`, { method: 'PUT', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['credentials', 'service'] }),
  });
}

export function useDeleteServiceCredential() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/credentials/service/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['credentials', 'service'] }),
  });
}

// ── Object scope rules (per model, by tenant or site) ────────────────────────

/** A per-model grant of an access group limited to selected inventory
 * groups: records of ``model`` (``*``: every model) whose tenant or site is
 * ``value_id``. */
export interface ScopeRule {
  model: string;
  attribute: 'tenant' | 'site';
  value_id: number;
  can_write: boolean;
}

/** One model of the server's object scope registry. */
export interface ScopeModelInfo {
  name: string;
  keys: string[];
  shared: boolean;
  description: string;
  rule_attributes: ('tenant' | 'site')[];
}

export function useObjectScopeModels(enabled = true) {
  return useQuery<ScopeModelInfo[]>({
    queryKey: ['admin', 'object-scope-models'],
    queryFn: ({ signal }) => apiRequest('/admin/object-scope/models', { signal }),
    enabled,
    staleTime: Infinity,
  });
}

export function useAccessGroupScopeRules(groupId: number | null) {
  return useQuery<ScopeRule[]>({
    queryKey: ['admin', 'access-groups', groupId, 'scope-rules'],
    queryFn: ({ signal }) => apiRequest(`/admin/access-groups/${groupId}/scope-rules`, { signal }),
    enabled: groupId != null,
  });
}

export function useSaveAccessGroupScopeRules() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ groupId, rules }: { groupId: number; rules: ScopeRule[] }) =>
      apiRequest<ScopeRule[]>(`/admin/access-groups/${groupId}/scope-rules`, { method: 'PUT', body: { rules } }),
    onSuccess: (_data, { groupId }) => {
      qc.invalidateQueries({ queryKey: ['admin', 'access-groups', groupId, 'scope-rules'] });
    },
  });
}
