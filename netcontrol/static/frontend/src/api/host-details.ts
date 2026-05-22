/**
 * Per-host data hooks for the topology NodeDetails tabs.
 *
 * All endpoints already exist -- this module is wiring, not new APIs.
 * Each hook is keyed by host_id and is gated on `enabled` so the topology
 * panel can lazy-fetch only the tab the operator opens.
 */
import { useQuery } from '@tanstack/react-query';

import { apiRequest } from './client';

// ── Interface inventory ────────────────────────────────────────────────────

export interface InterfaceInventoryRow {
  id: number;
  host_id: number;
  if_index: number;
  name: string;
  description: string;
  admin_state: string;
  oper_state: string;
  speed_mbps: number;
  duplex: string;
  last_change: string;
  access_vlan: number;
  trunk_vlans: string;
  collected_at?: string;
}

export function useHostInterfaceInventory(hostId: number | null, enabled = true) {
  return useQuery<{ host_id: number; interfaces: InterfaceInventoryRow[] }>({
    queryKey: ['host-interfaces', hostId],
    queryFn: () => apiRequest(`/hosts/${hostId}/interface-inventory`),
    enabled: enabled && hostId != null,
  });
}

// ── VLAN definitions ───────────────────────────────────────────────────────

export interface VlanDefinitionRow {
  id: number;
  host_id: number;
  vlan_id: number;
  name: string;
  state: string;
  collected_at?: string;
}

export function useHostVlans(hostId: number | null, enabled = true) {
  return useQuery<{ host_id: number; vlans: VlanDefinitionRow[] }>({
    queryKey: ['host-vlans', hostId],
    queryFn: () => apiRequest(`/hosts/${hostId}/vlans`),
    enabled: enabled && hostId != null,
  });
}

// ── MAC + ARP tables (existing /api/mac-tracking/host/{id}) ────────────────

export interface MacAddressRow {
  id: number;
  host_id: number;
  mac_address: string;
  vlan: number;
  port_name: string;
  port_index?: number;
  ip_address?: string;
  entry_type: string;
  first_seen?: string;
  last_seen?: string;
}

export interface ArpRow {
  id: number;
  host_id: number;
  ip_address: string;
  mac_address: string;
  interface_name: string;
  vrf?: string;
  first_seen?: string;
  last_seen?: string;
}

export function useHostMacArp(hostId: number | null, enabled = true) {
  return useQuery<{ mac_table: MacAddressRow[]; arp_table: ArpRow[] }>({
    queryKey: ['host-mac-arp', hostId],
    queryFn: () => apiRequest(`/mac-tracking/host/${hostId}`),
    enabled: enabled && hostId != null,
  });
}

// ── Config backups (existing /api/config-backups?host_id=...) ──────────────

export interface ConfigBackupRow {
  id: number;
  policy_id?: number | null;
  host_id: number;
  capture_method?: string;
  status: string;
  error_message?: string;
  captured_at: string;
  config_length?: number;
  hostname?: string;
  ip_address?: string;
  device_type?: string;
}

export function useHostConfigBackups(
  hostId: number | null,
  limit = 10,
  enabled = true,
) {
  return useQuery<ConfigBackupRow[]>({
    queryKey: ['host-config-backups', hostId, limit],
    queryFn: () =>
      apiRequest(`/config-backups?host_id=${hostId}&limit=${limit}`),
    enabled: enabled && hostId != null,
  });
}

// ── Interface errors (existing /api/interfaces/{host_id}/errors) ───────────

export interface InterfaceErrorMetric {
  sample_count: number;
  avg_value: number | null;
  max_value: number | null;
  min_value: number | null;
}

export interface InterfaceErrorRow {
  if_index?: number | null;
  if_name: string;
  metrics: Record<string, InterfaceErrorMetric>;
}

export interface InterfaceErrorSummary {
  host_id: number;
  days: number;
  interfaces: InterfaceErrorRow[];
  active_events: number;
}

export function useHostInterfaceErrors(
  hostId: number | null,
  days = 1,
  enabled = true,
) {
  return useQuery<InterfaceErrorSummary>({
    queryKey: ['host-interface-errors', hostId, days],
    queryFn: () => apiRequest(`/interfaces/${hostId}/errors?days=${days}`),
    enabled: enabled && hostId != null,
  });
}

// ── Audit findings scoped to one host ──────────────────────────────────────

export interface HostAuditFinding {
  id: number;
  run_id: number;
  host_id: number;
  rule_id: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cis_control?: string;
  title: string;
  detail?: string;
  evidence?: Record<string, unknown>;
  created_at?: string;
}

export function useHostAuditFindings(
  hostId: number | null,
  limit = 50,
  enabled = true,
) {
  return useQuery<{ host_id: number; findings: HostAuditFinding[] }>({
    queryKey: ['host-audit-findings', hostId, limit],
    queryFn: () =>
      apiRequest(`/hosts/${hostId}/audit-findings?limit=${limit}`),
    enabled: enabled && hostId != null,
  });
}
