/**
 * Circuits under /api/circuits: providers (with their provider networks),
 * circuit types, circuits with their A / Z terminations, the circuits that
 * land on a device, and the pickers' choices. Failures throw a
 * `CustomDataError`: a 422 carries per-field `fields` (termination fields as
 * `terminations.<A|Z>.<field>`), a 409 a duplicate name / circuit ID or a
 * delete of a record in use.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import type { CircuitFilter } from '@/lib/circuits';

import { queryString } from './client';
import { detailRequest, listOf } from './customData';

// ── Types ──────────────────────────────────────────────────────────────────

export type CircuitStatus = 'planned' | 'provisioning' | 'active' | 'offline' | 'deprovisioning' | 'decommissioned';
export type TermSide = 'A' | 'Z';

interface Stamps {
  created_by: string;
  created_at: string;
  updated_at: string;
  updated_by: string;
}

export interface CircuitProvider extends Stamps {
  id: number;
  name: string;
  account: string;
  portal_url: string;
  noc_contact: string;
  admin_contact: string;
  comments: string;
  circuit_count: number;
  network_count: number;
}

export interface ProviderNetwork extends Stamps {
  id: number;
  provider_id: number;
  provider_name: string;
  name: string;
  description: string;
  termination_count: number;
}

export interface CircuitType extends Stamps {
  id: number;
  name: string;
  description: string;
  circuit_count: number;
}

export interface CircuitTermination extends Stamps {
  id: number;
  circuit_id: number;
  term_side: TermSide;
  site_id: number | null;
  site_name: string | null;
  provider_network_id: number | null;
  provider_network_name: string | null;
  host_id: number | null;
  hostname: string | null;
  interface_name: string;
  port_speed_kbps: number | null;
  upstream_speed_kbps: number | null;
  xconnect_id: string;
  pp_info: string;
  description: string;
}

/** The latest rate of a termination's device port against the committed rate. */
export interface CircuitUtilisation {
  term_side: TermSide;
  host_id: number;
  interface_name: string;
  in_bps: number;
  out_bps: number;
  polled_at: string | null;
  commit_rate_kbps: number;
  in_pct_of_commit: number;
  out_pct_of_commit: number;
}

export interface Circuit extends Stamps {
  id: number;
  cid: string;
  provider_id: number;
  provider_name: string;
  circuit_type_id: number;
  circuit_type_name: string;
  status: CircuitStatus;
  tenant_id: number | null;
  tenant_name: string | null;
  install_date: string;
  termination_date: string;
  commit_rate_kbps: number | null;
  description: string;
  comments: string;
  billing_circuit_id: number | null;
  billing_circuit_name: string | null;
  billing_customer: string | null;
  terminations: CircuitTermination[];
  /** On the detail and device answers only. */
  utilisation?: CircuitUtilisation[];
}

export interface ProviderDetail extends CircuitProvider {
  networks: ProviderNetwork[];
}

export interface ProviderInput {
  name?: string;
  account?: string;
  portal_url?: string;
  noc_contact?: string;
  admin_contact?: string;
  comments?: string;
}

export interface ProviderNetworkInput {
  provider_id?: number;
  name?: string;
  description?: string;
}

export interface CircuitTypeInput {
  name?: string;
  description?: string;
}

export interface TerminationInput {
  term_side: TermSide;
  site_id: number | null;
  provider_network_id: number | null;
  host_id: number | null;
  interface_name: string;
  port_speed_kbps: number | null;
  upstream_speed_kbps: number | null;
  xconnect_id: string;
  pp_info: string;
  description: string;
}

export interface CircuitInput {
  cid: string;
  provider_id: number | null;
  circuit_type_id: number | null;
  status: CircuitStatus;
  tenant_id: number | null;
  install_date: string;
  termination_date: string;
  commit_rate_kbps: number | null;
  description: string;
  comments: string;
  billing_circuit_id: number | null;
  /** Replaces the circuit's terminations (a side left out is deleted). */
  terminations: TerminationInput[];
}

export interface CircuitChoices {
  hosts: { id: number; hostname: string; ip_address: string }[];
  sites: { id: number; name: string }[];
  tenants: { id: number; name: string }[];
}

// ── Query keys ─────────────────────────────────────────────────────────────

export const CIRCUITS_QUERY_ROOT = ['circuits'] as const;
const ROOT = CIRCUITS_QUERY_ROOT;
export const CIRCUIT_KEYS = {
  providers: [...ROOT, 'providers'] as const,
  provider: (id: number) => [...ROOT, 'provider', id] as const,
  networks: [...ROOT, 'networks'] as const,
  types: [...ROOT, 'types'] as const,
  circuits: (filter: CircuitFilter) => [...ROOT, 'list', filter] as const,
  circuit: (id: number) => [...ROOT, 'circuit', id] as const,
  hostCircuits: (hostId: number) => [...ROOT, 'host', hostId] as const,
  hostInterfaces: (hostId: number) => [...ROOT, 'host-interfaces', hostId] as const,
  choices: [...ROOT, 'choices'] as const,
};

type QC = ReturnType<typeof useQueryClient>;

/** Counts and names move together across every answer. */
function invalidateAll(qc: QC) {
  qc.invalidateQueries({ queryKey: ROOT });
  qc.invalidateQueries({ queryKey: ['object-changes'] });
}

// ── Queries ────────────────────────────────────────────────────────────────

export function useCircuitProviders() {
  return useQuery<CircuitProvider[]>({
    queryKey: CIRCUIT_KEYS.providers,
    queryFn: async ({ signal }) => listOf<CircuitProvider>(await detailRequest('/circuits/providers', { signal }), 'providers'),
  });
}

export function useCircuitProvider(id: number | null) {
  return useQuery<ProviderDetail>({
    queryKey: CIRCUIT_KEYS.provider(id ?? 0),
    queryFn: ({ signal }) => detailRequest<ProviderDetail>(`/circuits/providers/${id}`, { signal }),
    enabled: id !== null,
  });
}

export function useProviderNetworks() {
  return useQuery<ProviderNetwork[]>({
    queryKey: CIRCUIT_KEYS.networks,
    queryFn: async ({ signal }) =>
      listOf<ProviderNetwork>(await detailRequest('/circuits/provider-networks', { signal }), 'provider_networks'),
  });
}

export function useCircuitTypes() {
  return useQuery<CircuitType[]>({
    queryKey: CIRCUIT_KEYS.types,
    queryFn: async ({ signal }) => listOf<CircuitType>(await detailRequest('/circuits/circuit-types', { signal }), 'circuit_types'),
  });
}

export function useCircuits(filter: CircuitFilter) {
  return useQuery<Circuit[]>({
    queryKey: CIRCUIT_KEYS.circuits(filter),
    queryFn: async ({ signal }) => listOf<Circuit>(await detailRequest(`/circuits/circuits${queryString(filter)}`, { signal }), 'circuits'),
  });
}

export function useCircuit(id: number | null) {
  return useQuery<Circuit>({
    queryKey: CIRCUIT_KEYS.circuit(id ?? 0),
    queryFn: ({ signal }) => detailRequest<Circuit>(`/circuits/circuits/${id}`, { signal }),
    enabled: id !== null,
  });
}

/** The circuits with a termination on the device (with utilisation). */
export function useHostCircuits(hostId: number | null, enabled = true) {
  return useQuery<Circuit[]>({
    queryKey: CIRCUIT_KEYS.hostCircuits(hostId ?? 0),
    queryFn: async ({ signal }) => listOf<Circuit>(await detailRequest(`/circuits/hosts/${hostId}/circuits`, { signal }), 'circuits'),
    enabled: enabled && hostId !== null,
  });
}

/** The interface names Plexus knows for the device. */
export function useHostInterfaceNames(hostId: number | null) {
  return useQuery<string[]>({
    queryKey: CIRCUIT_KEYS.hostInterfaces(hostId ?? 0),
    queryFn: async ({ signal }) => listOf<string>(await detailRequest(`/circuits/hosts/${hostId}/interfaces`, { signal }), 'interfaces'),
    enabled: hostId !== null,
  });
}

export function useCircuitChoices() {
  return useQuery<CircuitChoices>({
    queryKey: CIRCUIT_KEYS.choices,
    queryFn: ({ signal }) => detailRequest<CircuitChoices>('/circuits/choices', { signal }),
  });
}

// ── Mutations ──────────────────────────────────────────────────────────────

function useWrite<TBody, TResult = unknown>(request: (body: TBody) => Promise<TResult>) {
  const qc = useQueryClient();
  return useMutation<TResult, Error, TBody>({ mutationFn: request, onSuccess: () => invalidateAll(qc) });
}

export function useSaveProvider() {
  return useWrite<{ id: number | null; data: ProviderInput }, CircuitProvider>(({ id, data }) =>
    detailRequest<CircuitProvider>(id === null ? '/circuits/providers' : `/circuits/providers/${id}`, {
      method: id === null ? 'POST' : 'PUT',
      body: data,
    }),
  );
}

/** Refused with a 409 while the provider has circuits or terminations in its networks. */
export function useDeleteProvider() {
  return useWrite<number>((id) => detailRequest(`/circuits/providers/${id}`, { method: 'DELETE' }));
}

export function useSaveProviderNetwork() {
  return useWrite<{ id: number | null; data: ProviderNetworkInput }, ProviderNetwork>(({ id, data }) =>
    detailRequest<ProviderNetwork>(id === null ? '/circuits/provider-networks' : `/circuits/provider-networks/${id}`, {
      method: id === null ? 'POST' : 'PUT',
      body: data,
    }),
  );
}

/** Refused with a 409 while a termination ends in the network. */
export function useDeleteProviderNetwork() {
  return useWrite<number>((id) => detailRequest(`/circuits/provider-networks/${id}`, { method: 'DELETE' }));
}

export function useSaveCircuitType() {
  return useWrite<{ id: number | null; data: CircuitTypeInput }, CircuitType>(({ id, data }) =>
    detailRequest<CircuitType>(id === null ? '/circuits/circuit-types' : `/circuits/circuit-types/${id}`, {
      method: id === null ? 'POST' : 'PUT',
      body: data,
    }),
  );
}

/** Refused with a 409 while circuits use the type. */
export function useDeleteCircuitType() {
  return useWrite<number>((id) => detailRequest(`/circuits/circuit-types/${id}`, { method: 'DELETE' }));
}

export function useSaveCircuit() {
  return useWrite<{ id: number | null; data: CircuitInput }, Circuit>(({ id, data }) =>
    detailRequest<Circuit>(id === null ? '/circuits/circuits' : `/circuits/circuits/${id}`, {
      method: id === null ? 'POST' : 'PUT',
      body: data,
    }),
  );
}

export function useDeleteCircuit() {
  return useWrite<number>((id) => detailRequest(`/circuits/circuits/${id}`, { method: 'DELETE' }));
}
