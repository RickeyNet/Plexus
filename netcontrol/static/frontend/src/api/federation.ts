import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

// ── Types ───────────────────────────────────────────────────────────────────

export interface FederationPeer {
  id: number;
  name: string;
  url: string;
  description?: string;
  enabled: boolean;
  has_token: boolean;
  last_sync_status?: string | null;
  last_sync_at?: string | null;
}

export interface FederationOverviewTotals {
  total_peers: number;
  healthy_peers: number;
  total_devices: number;
  devices_up: number;
  devices_down: number;
  total_alerts: number;
  critical_alerts: number;
}

export interface FederationPeerDetail {
  id: number;
  name: string;
  url: string;
  version?: string | null;
  last_sync_status?: string | null;
  last_sync_at?: string | null;
  devices?: { total?: number; up?: number; down?: number };
  alerts?: { active?: number };
  compliance?: { total_profiles?: number };
}

export interface FederationOverview {
  totals?: Partial<FederationOverviewTotals>;
  peers?: FederationPeerDetail[];
}

export interface FederationPeerInput {
  name: string;
  url: string;
  description?: string;
  enabled: boolean;
  api_token?: string;
}

export interface FederationTestResult {
  status: 'ok' | 'error';
  remote_version?: string | null;
  message?: string | null;
}

// ── Queries ────────────────────────────────────────────────────────────────

export function useFederationPeers() {
  return useQuery({
    queryKey: ['federation', 'peers'],
    queryFn: () => apiRequest<FederationPeer[]>('/federation/peers'),
  });
}

export function useFederationOverview() {
  return useQuery({
    queryKey: ['federation', 'overview'],
    queryFn: () => apiRequest<FederationOverview>('/federation/overview'),
  });
}

// ── Mutations ──────────────────────────────────────────────────────────────

function invalidateFederation(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: ['federation'] });
}

export function useCreateFederationPeer() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: FederationPeerInput) =>
      apiRequest<FederationPeer>('/federation/peers', { method: 'POST', body }),
    onSuccess: () => invalidateFederation(qc),
  });
}

export function useUpdateFederationPeer() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: number; body: FederationPeerInput }) =>
      apiRequest<FederationPeer>(`/federation/peers/${id}`, {
        method: 'PUT',
        body,
      }),
    onSuccess: () => invalidateFederation(qc),
  });
}

export function useDeleteFederationPeer() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest<void>(`/federation/peers/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateFederation(qc),
  });
}

export function useTestFederationPeer() {
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest<FederationTestResult>(`/federation/peers/${id}/test`, {
        method: 'POST',
      }),
  });
}

export function useSyncFederationPeer() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest<unknown>(`/federation/peers/${id}/sync`, { method: 'POST' }),
    onSuccess: () => invalidateFederation(qc),
  });
}
