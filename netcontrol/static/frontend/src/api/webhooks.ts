import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

// ── Outbound event webhooks (admin only) ────────────────────────────────────

export type WebhookAction = 'create' | 'update' | 'delete';

export interface Webhook {
  id: number;
  name: string;
  enabled: boolean;
  url: string;
  http_method: string;
  content_type: string;
  object_types: string[];
  actions: WebhookAction[] | string[];
  /** Field name -> allowed values, matched against the changed object. */
  filters: Record<string, (string | number)[]>;
  /** Header name -> value; stored values come back masked. */
  headers: Record<string, string>;
  has_secret: boolean;
  /** The mask when a secret is stored, else empty. */
  secret: string;
  body_template: string;
  verify_tls: boolean;
  ca_bundle: string;
  timeout_seconds: number;
  max_retries: number;
  concurrency: number;
  created_by?: string;
  created_at?: string;
  updated_at?: string;
}

/** What the editor sends: `secret` null or the mask keeps the stored one, "" clears it. */
export type WebhookPayload = Omit<Webhook, 'id' | 'has_secret' | 'created_by' | 'created_at' | 'updated_at'> & {
  secret: string | null;
};

export interface WebhookStats {
  id: number;
  queue_depth: number;
  queue_size: number;
  delivered: number;
  failed: number;
  dropped_queue_full: number;
  last_error: string;
  last_delivery_at: string;
  last_failure_at: string;
}

export interface WebhooksResponse {
  webhooks: Webhook[];
  stats: WebhookStats[];
  object_types: string[];
  actions: string[];
}

export type DeliveryStatus = 'success' | 'retrying' | 'failed' | 'blocked' | string;

export interface WebhookDelivery {
  id: number;
  webhook_id: number;
  delivery_id: string;
  event: string;
  object_type: string;
  object_id: string;
  action: string;
  attempt: number;
  status: DeliveryStatus;
  status_code: number | null;
  latency_ms: number | null;
  response_body: string;
  error: string;
  created_at: string;
}

export interface WebhookSendResult {
  ok: boolean;
  status: DeliveryStatus;
  status_code: number | null;
  latency_ms: number | null;
  error: string;
  delivery_id: string;
}

const KEY = ['admin', 'webhooks'] as const;

/** The list refetches every 15 s for the delivery counters while the tab is open. */
export function useWebhooks() {
  return useQuery<WebhooksResponse>({
    queryKey: KEY,
    queryFn: ({ signal }) => apiRequest('/admin/webhooks', { signal }),
    refetchInterval: 15_000,
  });
}

export function useWebhookDeliveries(id: number | null) {
  return useQuery<{ deliveries: WebhookDelivery[] }>({
    queryKey: ['admin', 'webhook-deliveries', id],
    queryFn: ({ signal }) => apiRequest(`/admin/webhooks/${id}/deliveries?limit=200`, { signal }),
    enabled: id != null,
  });
}

export function useCreateWebhook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: WebhookPayload) => apiRequest<Webhook>('/admin/webhooks', { method: 'POST', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useUpdateWebhook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: WebhookPayload }) =>
      apiRequest<Webhook>(`/admin/webhooks/${id}`, { method: 'PUT', body: data }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useDeleteWebhook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => apiRequest<{ ok: boolean }>(`/admin/webhooks/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

export function useTestWebhook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => apiRequest<WebhookSendResult>(`/admin/webhooks/${id}/test`, { method: 'POST' }),
    onSuccess: (_res, id) => qc.invalidateQueries({ queryKey: ['admin', 'webhook-deliveries', id] }),
  });
}

export function useRedeliverWebhook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, deliveryRowId }: { id: number; deliveryRowId: number }) =>
      apiRequest<WebhookSendResult>(`/admin/webhooks/${id}/deliveries/${deliveryRowId}/redeliver`, {
        method: 'POST',
      }),
    onSuccess: (_res, { id }) => qc.invalidateQueries({ queryKey: ['admin', 'webhook-deliveries', id] }),
  });
}
