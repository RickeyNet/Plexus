/**
 * Routing objects under /api/routing: autonomous systems, routing instances,
 * BGP peer groups and BGP peerings (the intended BGP state of devices), the
 * comparison with the BGP neighbors Plexus discovers, and suggestions from
 * those neighbors. Failures throw a `CustomDataError`: a 422 carries a
 * message per field, a duplicate is a 409, and deleting an AS in use is a
 * 409 whose message says what uses it.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import type { ComplianceState } from '@/lib/routing';

import { queryString } from './client';
import { detailRequest, listOf } from './customData';

// ── Types ──────────────────────────────────────────────────────────────────

interface Stamps {
  created_by: string;
  created_at: string;
  updated_by: string;
  updated_at: string;
}

export interface AutonomousSystem extends Stamps {
  id: number;
  asn: number;
  description: string;
  tenant_id: number | null;
  tenant_name: string;
  /** The registry that assigned it (free text). */
  rir: string;
  comments: string;
  /** Routing instances whose local AS this is. */
  instance_count: number;
  /** Peerings whose remote AS this is. */
  peering_count: number;
}

export type InstanceStatus = 'planned' | 'active' | 'decommissioned';
export type PeeringStatus = 'planned' | 'active' | 'disabled' | 'decommissioned';

export interface RoutingInstance extends Stamps {
  id: number;
  host_id: number;
  hostname: string;
  name: string;
  vrf_id: number | null;
  vrf_name: string;
  autonomous_system_id: number;
  /** The local AS number. */
  asn: number;
  router_id: string;
  status: InstanceStatus;
  description: string;
  peering_count: number;
  peer_group_count: number;
}

export interface BgpPeerGroup extends Stamps {
  id: number;
  routing_instance_id: number;
  routing_instance_name: string;
  host_id: number;
  hostname: string;
  name: string;
  remote_asn_id: number | null;
  remote_asn: number | null;
  import_policy: string;
  export_policy: string;
  description: string;
  peering_count: number;
}

export interface BgpPeering extends Stamps {
  id: number;
  routing_instance_id: number;
  routing_instance_name: string;
  host_id: number;
  hostname: string;
  local_asn: number;
  peer_group_id: number | null;
  peer_group_name: string;
  local_address: string;
  remote_address: string;
  remote_asn_id: number;
  remote_asn: number;
  remote_host_id: number | null;
  remote_hostname: string;
  status: PeeringStatus;
  address_families: string[];
  import_policy: string;
  export_policy: string;
  description: string;
}

export interface AutonomousSystemDetail extends AutonomousSystem {
  routing_instances: RoutingInstance[];
  peerings: BgpPeering[];
}

export interface RoutingInstanceDetail extends RoutingInstance {
  peer_groups: BgpPeerGroup[];
  peerings: BgpPeering[];
}

export interface ComplianceRow {
  state: ComplianceState;
  host_id: number;
  hostname: string;
  /** null for an unexpected neighbor. */
  peering_id: number | null;
  routing_instance_id: number | null;
  routing_instance: string;
  status: PeeringStatus | null;
  remote_address: string;
  intended_remote_asn: number | null;
  observed_remote_asn: number | null;
  /** The BGP session state the device reported ('' when not observed). */
  observed_state: string;
  discovered_at: string;
  detail: string;
}

export type ComplianceCounts = Record<ComplianceState, number>;

export interface ComplianceHost {
  host_id: number;
  hostname: string;
  /** Whether the device's neighbors were ever discovered. */
  has_data: boolean;
  last_discovered_at: string;
  counts: ComplianceCounts;
}

export interface ComplianceReport {
  rows: ComplianceRow[];
  summary: ComplianceCounts;
  hosts: ComplianceHost[];
}

export interface SuggestedPeering {
  remote_address: string;
  remote_asn: number | null;
  observed_state: string;
  established: boolean;
  status: 'active' | 'planned';
  remote_host_id: number | null;
  remote_hostname: string;
}

export interface Suggestions {
  host_id: number;
  hostname: string;
  has_data: boolean;
  routing_instances: { id: number; name: string; asn: number }[];
  proposed_instance: { name: string; asn: number | null } | null;
  autonomous_systems: { asn: number; autonomous_system_id: number | null }[];
  peerings: SuggestedPeering[];
}

export interface SuggestionAccept {
  host_id: number;
  routing_instance_id?: number | null;
  new_instance?: { name: string; asn: number | string; router_id?: string; status?: 'planned' | 'active' } | null;
  peerings: { remote_address: string; remote_asn?: number | null; status: 'planned' | 'active'; remote_host_id?: number | null }[];
}

export interface SuggestionResult {
  autonomous_systems: AutonomousSystem[];
  routing_instance: RoutingInstance | null;
  peerings: BgpPeering[];
}

export interface AutonomousSystemInput {
  asn?: number | string;
  description?: string;
  tenant_id?: number | null;
  rir?: string;
  comments?: string;
}

export interface RoutingInstanceInput {
  host_id?: number;
  name?: string;
  vrf_id?: number | null;
  autonomous_system_id?: number | null;
  router_id?: string;
  status?: InstanceStatus;
  description?: string;
}

export interface PeerGroupInput {
  routing_instance_id?: number;
  name?: string;
  remote_asn_id?: number | null;
  import_policy?: string;
  export_policy?: string;
  description?: string;
}

export interface PeeringInput {
  routing_instance_id?: number;
  peer_group_id?: number | null;
  local_address?: string;
  remote_address?: string;
  remote_asn_id?: number | null;
  remote_host_id?: number | null;
  status?: PeeringStatus;
  address_families?: string[];
  import_policy?: string;
  export_policy?: string;
  description?: string;
}

export interface InstanceFilter {
  host_id?: number | null;
  asn?: string;
  status?: string;
  tenant_id?: number | null;
  search?: string;
}

export interface PeeringFilter extends InstanceFilter {
  routing_instance_id?: number | null;
}

// ── Query keys ─────────────────────────────────────────────────────────────

export const ROUTING_QUERY_ROOT = ['routing'] as const;
const ROOT = ROUTING_QUERY_ROOT;
export const ROUTING_KEYS = {
  ases: (search: string) => [...ROOT, 'ases', search] as const,
  as: (id: number) => [...ROOT, 'as', id] as const,
  instances: (filter: InstanceFilter) => [...ROOT, 'instances', filter] as const,
  instance: (id: number) => [...ROOT, 'instance', id] as const,
  peerGroups: (filter: { host_id?: number | null; search?: string }) => [...ROOT, 'peer-groups', filter] as const,
  peerings: (filter: PeeringFilter) => [...ROOT, 'peerings', filter] as const,
  peering: (id: number) => [...ROOT, 'peering', id] as const,
  compliance: (hostId: number | null) => [...ROOT, 'compliance', hostId] as const,
  suggestions: (hostId: number) => [...ROOT, 'suggestions', hostId] as const,
};

type QC = ReturnType<typeof useQueryClient>;

/** Counts and compliance move together: refresh every routing answer. */
function invalidateAll(qc: QC) {
  qc.invalidateQueries({ queryKey: ROOT });
}

const BASE = '/routing';

// ── Queries ────────────────────────────────────────────────────────────────

export function useAutonomousSystems(search = '') {
  return useQuery<AutonomousSystem[]>({
    queryKey: ROUTING_KEYS.ases(search),
    queryFn: async () =>
      listOf<AutonomousSystem>(await detailRequest(`${BASE}/autonomous-systems${queryString({ search })}`), 'autonomous_systems'),
  });
}

export function useAutonomousSystem(id: number | null) {
  return useQuery<AutonomousSystemDetail>({
    queryKey: ROUTING_KEYS.as(id ?? 0),
    queryFn: () => detailRequest<AutonomousSystemDetail>(`${BASE}/autonomous-systems/${id}`),
    enabled: id !== null,
  });
}

export function useRoutingInstances(filter: InstanceFilter = {}, enabled = true) {
  return useQuery<RoutingInstance[]>({
    queryKey: ROUTING_KEYS.instances(filter),
    queryFn: async () => listOf<RoutingInstance>(await detailRequest(`${BASE}/instances${queryString(filter)}`), 'routing_instances'),
    enabled,
  });
}

export function useRoutingInstance(id: number | null) {
  return useQuery<RoutingInstanceDetail>({
    queryKey: ROUTING_KEYS.instance(id ?? 0),
    queryFn: () => detailRequest<RoutingInstanceDetail>(`${BASE}/instances/${id}`),
    enabled: id !== null,
  });
}

export function useBgpPeerGroups(filter: { host_id?: number | null; search?: string } = {}) {
  return useQuery<BgpPeerGroup[]>({
    queryKey: ROUTING_KEYS.peerGroups(filter),
    queryFn: async () => listOf<BgpPeerGroup>(await detailRequest(`${BASE}/peer-groups${queryString(filter)}`), 'peer_groups'),
  });
}

export function useBgpPeerings(filter: PeeringFilter = {}, enabled = true) {
  return useQuery<BgpPeering[]>({
    queryKey: ROUTING_KEYS.peerings(filter),
    queryFn: async () => listOf<BgpPeering>(await detailRequest(`${BASE}/peerings${queryString(filter)}`), 'peerings'),
    enabled,
  });
}

export function useBgpPeering(id: number | null) {
  return useQuery<BgpPeering>({
    queryKey: ROUTING_KEYS.peering(id ?? 0),
    queryFn: () => detailRequest<BgpPeering>(`${BASE}/peerings/${id}`),
    enabled: id !== null,
  });
}

/** Intended vs observed; `hostId` null: every device with a routing instance. */
export function useRoutingCompliance(hostId: number | null, enabled = true) {
  return useQuery<ComplianceReport>({
    queryKey: ROUTING_KEYS.compliance(hostId),
    queryFn: () => detailRequest<ComplianceReport>(`${BASE}/compliance${queryString({ host_id: hostId })}`),
    enabled,
  });
}

export function useRoutingSuggestions(hostId: number | null) {
  return useQuery<Suggestions>({
    queryKey: ROUTING_KEYS.suggestions(hostId ?? 0),
    queryFn: () => detailRequest<Suggestions>(`${BASE}/suggestions${queryString({ host_id: hostId })}`),
    enabled: hostId !== null,
  });
}

// ── Mutations ──────────────────────────────────────────────────────────────

function useWrite<V, R>(fn: (vars: V) => Promise<R>) {
  const qc = useQueryClient();
  return useMutation({ mutationFn: fn, onSuccess: () => invalidateAll(qc) });
}

const json = (method: string, body: unknown) => ({ method, body });

function crud<T, I>(path: string) {
  return {
    create: (data: I) => detailRequest<T>(`${BASE}/${path}`, json('POST', data)),
    update: ({ id, data }: { id: number; data: I }) => detailRequest<T>(`${BASE}/${path}/${id}`, json('PUT', data)),
    remove: (id: number) => detailRequest<{ ok: boolean }>(`${BASE}/${path}/${id}`, { method: 'DELETE' }),
  };
}

const AS_API = crud<AutonomousSystem, AutonomousSystemInput>('autonomous-systems');
const INSTANCE_API = crud<RoutingInstance, RoutingInstanceInput>('instances');
const GROUP_API = crud<BgpPeerGroup, PeerGroupInput>('peer-groups');
const PEERING_API = crud<BgpPeering, PeeringInput>('peerings');

export const useCreateAutonomousSystem = () => useWrite(AS_API.create);
export const useUpdateAutonomousSystem = () => useWrite(AS_API.update);
export const useDeleteAutonomousSystem = () => useWrite(AS_API.remove);
export const useCreateRoutingInstance = () => useWrite(INSTANCE_API.create);
export const useUpdateRoutingInstance = () => useWrite(INSTANCE_API.update);
export const useDeleteRoutingInstance = () => useWrite(INSTANCE_API.remove);
export const useCreatePeerGroup = () => useWrite(GROUP_API.create);
export const useUpdatePeerGroup = () => useWrite(GROUP_API.update);
export const useDeletePeerGroup = () => useWrite(GROUP_API.remove);
export const useCreatePeering = () => useWrite(PEERING_API.create);
export const useUpdatePeering = () => useWrite(PEERING_API.update);
export const useDeletePeering = () => useWrite(PEERING_API.remove);

export const useAcceptSuggestions = () =>
  useWrite((data: SuggestionAccept) => detailRequest<SuggestionResult>(`${BASE}/suggestions/accept`, json('POST', data)));
