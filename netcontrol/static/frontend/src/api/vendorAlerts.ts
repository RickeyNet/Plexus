/**
 * Vendor alert feeds (the Cato events feed, AWS, Azure): the alert list
 * (monitoring access) and the admin-only settings and Poll Now of each feed.
 * Backend endpoints under /api/monitoring/vendor-alerts.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

export interface VendorAlert {
  id: number;
  provider: string;
  alert_key: string;
  org_ref: number;
  org_name: string;
  /** The entity as the availability tracker names it: site, uplink, port... */
  entity_type: string;
  entity_id: string;
  entity_name: string;
  site: string;
  serial: string;
  condition: string;
  event_type: string;
  event_sub_type: string;
  title: string;
  message: string;
  severity: 'critical' | 'warning' | 'info' | string;
  status: 'open' | 'resolved';
  /** A one-shot event with no recovery event: closed after the open TTL. */
  auto_expire: boolean;
  started_at: string;
  resolved_at: string;
  first_seen: string;
  last_seen: string;
  occurrences: number;
  host_id: number | null;
  /**
   * How Plexus alerted: ``monitoring``, ``notification``, ``topology``
   * (already notified by the availability tracker), ``muted`` or empty.
   */
  alert_via: string;
  muted?: boolean;
}

export interface VendorAlertConfig {
  poll_enabled: boolean;
  interval_seconds: number;
  excluded_sources: number[];
  open_ttl_hours: number;
  security_events: boolean;
  /** The parts switched off (AWS and Azure feeds only). */
  disabled_parts?: string[];
}

/** One part of a feed that can be switched off (CloudWatch alarms, Resource Health...). */
export interface VendorAlertPart {
  key: string;
  label: string;
  enabled: boolean;
}

export interface VendorAlertSourceStatus {
  id: number;
  name: string;
  has_api_key: boolean;
  excluded: boolean;
  last_poll_at: string;
  last_ok_at: string;
  last_error: string;
  /** ``ok``, ``positioned``, ``partial``, ``refused``, ``no_access``, ``rate_limited``, ``unreachable``, ``error`` or empty. */
  feed_status: string;
  cursor_set: boolean;
  last_event_at: string;
  events_read: number;
  next_poll_at: string;
}

export interface VendorAlertSettings {
  provider: string;
  label: string;
  description: string;
  /** A current-state read (AWS, Azure): no cursor, an alert closes when a complete read no longer reports it. */
  current_state: boolean;
  parts: VendorAlertPart[];
  config: VendorAlertConfig;
  min_interval_seconds: number;
  max_interval_seconds: number;
  status: { last_poll_at: string; last_poll_ok: boolean | null; last_poll_error: string };
  sources: VendorAlertSourceStatus[];
}

export type VendorAlertSettingsUpdate = Partial<VendorAlertConfig>;

export interface VendorAlertPollResult {
  ok: boolean;
  polled: number;
  failed?: number;
  skipped?: number | string;
  new?: number;
  resolved?: number;
  alerted?: number;
  security?: number;
  error?: string;
}

export function useVendorAlerts(provider: string, includeResolved = false) {
  return useQuery<{ alerts: VendorAlert[] }>({
    queryKey: ['vendor-alerts', provider, includeResolved],
    queryFn: () =>
      apiRequest(
        `/monitoring/vendor-alerts?provider=${encodeURIComponent(provider)}&include_resolved=${includeResolved}`,
      ),
  });
}

/** A feed's settings and the poll status of each source (administrators only). */
export function useVendorAlertSettings(provider: string, enabled: boolean) {
  return useQuery<VendorAlertSettings>({
    queryKey: ['vendor-alert-settings', provider],
    queryFn: () => apiRequest(`/monitoring/vendor-alerts/${encodeURIComponent(provider)}/settings`),
    enabled,
  });
}

export function useUpdateVendorAlertSettings(provider: string) {
  const qc = useQueryClient();
  return useMutation<VendorAlertSettings, Error, VendorAlertSettingsUpdate>({
    mutationFn: (body) =>
      apiRequest(`/monitoring/vendor-alerts/${encodeURIComponent(provider)}/settings`, { method: 'PUT', body }),
    onSuccess: (data) => qc.setQueryData(['vendor-alert-settings', provider], data),
  });
}

/** Poll every enabled source of a feed now. */
export function usePollVendorAlerts(provider: string) {
  const qc = useQueryClient();
  return useMutation<VendorAlertPollResult, Error, void>({
    mutationFn: () =>
      apiRequest(`/monitoring/vendor-alerts/${encodeURIComponent(provider)}/poll`, { method: 'POST' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['vendor-alerts', provider] });
      qc.invalidateQueries({ queryKey: ['vendor-alert-settings', provider] });
    },
  });
}
