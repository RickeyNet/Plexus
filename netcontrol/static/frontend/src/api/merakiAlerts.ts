/**
 * Near-real-time Meraki alerts: the alert list (monitoring access) and the
 * admin-only settings of the assurance-alert poll and the webhook receiver.
 * Backend endpoints under /api/monitoring/meraki-alerts.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

export type MerakiAlertSeverity = 'critical' | 'warning' | 'info';

export interface MerakiAlert {
  id: number;
  alert_key: string;
  org_ref: number;
  org_name: string;
  network_id: string;
  network_name: string;
  device_serial: string;
  device_name: string;
  device_model: string;
  product_type: string;
  alert_type: string;
  condition: string;
  category: string;
  title: string;
  message: string;
  severity: MerakiAlertSeverity | string;
  status: 'open' | 'resolved';
  started_at: string;
  resolved_at: string;
  first_seen: string;
  last_seen: string;
  /** The paths that reported it: ``poll`` and/or ``webhook``. */
  seen_via: string[];
  occurrences: number;
  host_id: number | null;
  /**
   * How Plexus alerted: ``monitoring``, ``notification``, ``topology``,
   * ``muted`` (stored but not raised) or empty (not alerted).
   */
  alert_via: string;
  /** Its device or network is muted; absent from older servers. */
  muted?: boolean;
}

export interface MerakiAlertSettingsConfig {
  poll_enabled: boolean;
  interval_seconds: number;
  webhook_enabled: boolean;
  /** The secret itself is never returned. */
  webhook_secret_configured: boolean;
  excluded_sources: number[];
  webhook_open_ttl_hours: number;
}

export interface MerakiAlertSourceStatus {
  id: number;
  name: string;
  has_api_key: boolean;
  excluded: boolean;
  last_poll_at: string;
  last_ok_at: string;
  last_error: string;
}

export interface MerakiAlertSettings {
  config: MerakiAlertSettingsConfig;
  webhook_active: boolean;
  webhook_path: string;
  min_interval_seconds: number;
  max_interval_seconds: number;
  status: {
    last_poll_at: string;
    last_poll_ok: boolean | null;
    last_poll_error: string;
    last_webhook_at: string;
    last_test_at: string;
    last_webhook_error: string;
    webhooks_accepted: number;
    webhooks_rejected: number;
    unknown_org_events: number;
  };
  sources: MerakiAlertSourceStatus[];
}

export interface MerakiAlertSettingsUpdate {
  poll_enabled?: boolean;
  interval_seconds?: number;
  webhook_enabled?: boolean;
  /** Write-only: sets or rotates the shared secret. */
  webhook_secret?: string;
  clear_webhook_secret?: boolean;
  excluded_sources?: number[];
}

export interface MerakiAlertPollResult {
  ok: boolean;
  polled: number;
  failed?: number;
  new?: number;
  resolved?: number;
  alerted?: number;
  error?: string;
}

export function useMerakiAlerts(includeResolved = false) {
  return useQuery<{ alerts: MerakiAlert[] }>({
    queryKey: ['meraki-alerts', includeResolved],
    queryFn: () => apiRequest(`/monitoring/meraki-alerts?include_resolved=${includeResolved}`),
  });
}

/** The poll and webhook settings and status (administrators only). */
export function useMerakiAlertSettings(enabled: boolean) {
  return useQuery<MerakiAlertSettings>({
    queryKey: ['meraki-alert-settings'],
    queryFn: () => apiRequest('/monitoring/meraki-alerts/settings'),
    enabled,
  });
}

export function useUpdateMerakiAlertSettings() {
  const qc = useQueryClient();
  return useMutation<MerakiAlertSettings, Error, MerakiAlertSettingsUpdate>({
    mutationFn: (body) => apiRequest('/monitoring/meraki-alerts/settings', { method: 'PUT', body }),
    onSuccess: (data) => qc.setQueryData(['meraki-alert-settings'], data),
  });
}

/** Poll every enabled Meraki organization now. */
export function usePollMerakiAlerts() {
  const qc = useQueryClient();
  return useMutation<MerakiAlertPollResult, Error, void>({
    mutationFn: () => apiRequest('/monitoring/meraki-alerts/poll', { method: 'POST' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['meraki-alerts'] });
      qc.invalidateQueries({ queryKey: ['meraki-alert-settings'] });
    },
  });
}
