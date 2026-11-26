/**
 * Security events: the intrusion detection (Suricata) alerts integrations
 * read from a device, today OPNsense firewalls. Monitoring access.
 * Backend endpoint: GET /api/monitoring/security-events.
 */
import { keepPreviousData, useQuery } from '@tanstack/react-query';

import { apiRequest } from './client';

export type SecurityEventSeverity = 'critical' | 'warning' | 'info' | 'unknown';

export interface SecurityEvent {
  id: number;
  provider: string;
  org_ref: number;
  source_name: string;
  host_id: number | null;
  hostname: string | null;
  kind: string;
  /** When it happened at the device (UTC "YYYY-MM-DD HH:MM:SS"). */
  occurred_at: string;
  received_at: string;
  severity: SecurityEventSeverity | string;
  priority: number | null;
  signature_id: number | null;
  signature: string;
  category: string;
  /** What the device did: ``allowed`` (detected only) or ``blocked``. */
  action: string;
  protocol: string;
  src_ip: string;
  src_port: number | null;
  dest_ip: string;
  dest_port: number | null;
  interface: string;
  flow_id: string;
  app_proto: string;
}

export interface SecurityEventCounts {
  critical: number;
  warning: number;
  info: number;
  unknown: number;
  blocked: number;
}

export interface SecurityEventList {
  events: SecurityEvent[];
  total: number;
  counts: SecurityEventCounts;
  since: string;
  hours: number;
  limit: number;
  offset: number;
}

export interface SecurityEventFilters {
  hours: number;
  severity?: string;
  action?: string;
  q?: string;
  hostId?: number;
  orgRef?: number;
  limit?: number;
  offset?: number;
}

/** The query string of a list request (empty filters left out). */
export function securityEventQuery(filters: SecurityEventFilters): string {
  const qs = new URLSearchParams();
  qs.set('hours', String(filters.hours));
  if (filters.severity) qs.set('severity', filters.severity);
  if (filters.action) qs.set('action', filters.action);
  const q = filters.q?.trim();
  if (q) qs.set('q', q);
  if (filters.hostId != null) qs.set('host_id', String(filters.hostId));
  if (filters.orgRef != null) qs.set('org_ref', String(filters.orgRef));
  if (filters.limit != null) qs.set('limit', String(filters.limit));
  if (filters.offset) qs.set('offset', String(filters.offset));
  return qs.toString();
}

export function useSecurityEvents(filters: SecurityEventFilters) {
  const query = securityEventQuery(filters);
  return useQuery<SecurityEventList>({
    queryKey: ['security-events', query],
    queryFn: ({ signal }) => apiRequest(`/monitoring/security-events?${query}`, { signal }),
    placeholderData: keepPreviousData,
    refetchInterval: 60_000,
  });
}
