/**
 * VRF and VLAN records under /api/ipam, and the addresses a device's
 * interfaces carry (read from its stored running configuration). Failures
 * throw a `CustomDataError`: a VRF delete refused while the name is in use
 * is a 409 whose message says what uses it, an unknown `site_id` a 400
 * naming the field.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { vlanListPath, type VlanSiteFilter } from '@/lib/networkObjects';

import { detailRequest, listOf } from './customData';

// ── Types ──────────────────────────────────────────────────────────────────

/** `manual`: created by an admin; `discovered`: created from collected data. */
export type NetworkObjectOrigin = 'manual' | 'discovered';

export interface Vrf {
  id: number;
  name: string;
  /** Route distinguisher ('' when unset). */
  rd: string;
  description: string;
  origin: NetworkObjectOrigin | string;
  created_at: string;
  /** Hosts whose inventory VRF is this name. */
  host_count: number;
  /** Devices with an interface or static route in the VRF. */
  device_count: number;
  prefix_count: number;
  /** Interface addresses in the VRF. */
  address_count: number;
}

export interface SiteRef {
  id: number;
  name: string;
}

export interface Vlan {
  id: number;
  /** The VLAN id, 1 to 4094. */
  vid: number;
  name: string;
  /** The site, or null for a VLAN of no site (global). */
  site_id: number | null;
  site: SiteRef | null;
  description: string;
  origin: NetworkObjectOrigin | string;
  created_at: string;
  device_count: number;
  /** Ports of those devices in the VLAN. */
  interface_count: number;
  prefix_count: number;
  /** A device that resolves to the record names the VLAN differently. */
  name_mismatch: boolean;
}

/** `primary`, `secondary`, or `virtual` (an HSRP / VRRP / GLBP address). */
export type InterfaceAddressRole = 'primary' | 'secondary' | 'virtual';

export interface InterfaceAddress {
  host_id: number;
  hostname: string;
  /** The interface name as the configuration spells it. */
  interface: string;
  address: string;
  prefix_length: number;
  /** The interface's network in CIDR form. */
  network: string;
  /** '' for the global VRF. */
  vrf_name: string;
  role: InterfaceAddressRole | string;
  /** '' unless the role is virtual: HSRP, VRRP or GLBP. */
  protocol: string;
  /** The VLAN id when the interface is a VLAN interface, else 0. */
  svi_vid: number;
  collected_at: string;
}

export interface VrfDetail extends Vrf {
  devices: { host_id: number; hostname: string; interface_count: number }[];
  /** At most 2000; `truncated` says more exist. */
  interfaces: InterfaceAddress[];
  truncated?: boolean;
  /** `source`: the IPAM source's provider, or `interface`. */
  prefixes: { subnet: string; source: string }[];
}

export interface VlanDevice {
  host_id: number;
  hostname: string;
  /** The device's own name for the VLAN. */
  name: string;
  state: string;
  name_matches: boolean;
}

export interface VlanPort {
  host_id: number;
  hostname: string;
  interface: string;
  mode: 'access' | 'trunk' | string;
}

export interface VlanPrefix {
  network: string;
  vrf_name: string;
  host_id: number;
  hostname: string;
  interface: string;
  address: string;
}

export interface VlanDetail extends Vlan {
  devices: VlanDevice[];
  /** At most 2000; `truncated` says more exist. */
  interfaces: VlanPort[];
  truncated?: boolean;
  prefixes: VlanPrefix[];
}

/** An address of a host's interface, linked to its VRF and VLAN records when they exist. */
export interface HostInterfaceAddress extends InterfaceAddress {
  vrf_id: number | null;
  vlan_id: number | null;
}

export interface HostInterfaceAddresses {
  host_id: number;
  addresses: HostInterfaceAddress[];
  vrfs: { name: string; vrf_id: number | null; interface_count: number }[];
}

export interface VrfCreate {
  name: string;
  rd?: string;
  description?: string;
}

/** The name of a VRF cannot change. */
export interface VrfUpdate {
  rd?: string;
  description?: string;
}

export interface VlanCreate {
  vid: number;
  name?: string;
  site_id?: number | null;
  description?: string;
}

/** The VLAN id cannot change. */
export interface VlanUpdate {
  name?: string;
  site_id?: number | null;
  description?: string;
}

export interface RebuildResult {
  ok: boolean;
  hosts: number;
  addresses: number;
}

// ── Query keys ─────────────────────────────────────────────────────────────

export const NETWORK_OBJECTS_QUERY_ROOT = ['network-objects'] as const;
const ROOT = NETWORK_OBJECTS_QUERY_ROOT;
export const NETWORK_OBJECT_KEYS = {
  vrfs: [...ROOT, 'vrfs'] as const,
  vrf: (id: number) => [...ROOT, 'vrf', id] as const,
  vlans: (site: VlanSiteFilter) => [...ROOT, 'vlans', site] as const,
  vlan: (id: number) => [...ROOT, 'vlan', id] as const,
  hostAddresses: (hostId: number) => [...ROOT, 'host-addresses', hostId] as const,
};

type QC = ReturnType<typeof useQueryClient>;

/** Every list, detail and host address answer (their counts move together). */
function invalidateAll(qc: QC) {
  qc.invalidateQueries({ queryKey: ROOT });
}

// ── Queries ────────────────────────────────────────────────────────────────

/** Every VRF, by name. */
export function useVrfs() {
  return useQuery<Vrf[]>({
    queryKey: NETWORK_OBJECT_KEYS.vrfs,
    queryFn: async () => listOf<Vrf>(await detailRequest('/ipam/vrfs'), 'vrfs'),
  });
}

export function useVrf(id: number | null) {
  return useQuery<VrfDetail>({
    queryKey: NETWORK_OBJECT_KEYS.vrf(id ?? 0),
    queryFn: () => detailRequest<VrfDetail>(`/ipam/vrfs/${id}`),
    enabled: id !== null,
  });
}

/** VLANs by site name then VLAN id; `site` narrows to one site (`'none'`: VLANs of no site). */
export function useVlans(site: VlanSiteFilter = 'all') {
  return useQuery<Vlan[]>({
    queryKey: NETWORK_OBJECT_KEYS.vlans(site),
    queryFn: async () => listOf<Vlan>(await detailRequest(vlanListPath(site)), 'vlans'),
  });
}

export function useVlan(id: number | null) {
  return useQuery<VlanDetail>({
    queryKey: NETWORK_OBJECT_KEYS.vlan(id ?? 0),
    queryFn: () => detailRequest<VlanDetail>(`/ipam/vlans/${id}`),
    enabled: id !== null,
  });
}

/** The addresses the host's interfaces carry, from its newest stored configuration. */
export function useHostInterfaceAddresses(hostId: number | null, enabled = true) {
  return useQuery<HostInterfaceAddresses>({
    queryKey: NETWORK_OBJECT_KEYS.hostAddresses(hostId ?? 0),
    queryFn: () => detailRequest<HostInterfaceAddresses>(`/hosts/${hostId}/interface-addresses`),
    enabled: enabled && hostId !== null,
  });
}

// ── Mutations (admin) ──────────────────────────────────────────────────────

export function useCreateVrf() {
  const qc = useQueryClient();
  return useMutation<Vrf, Error, VrfCreate>({
    mutationFn: (data) => detailRequest<Vrf>('/ipam/vrfs', { method: 'POST', body: data }),
    onSuccess: () => invalidateAll(qc),
  });
}

export function useUpdateVrf() {
  const qc = useQueryClient();
  return useMutation<Vrf, Error, { id: number; data: VrfUpdate }>({
    mutationFn: ({ id, data }) => detailRequest<Vrf>(`/ipam/vrfs/${id}`, { method: 'PUT', body: data }),
    onSuccess: () => invalidateAll(qc),
  });
}

/** Refused with a 409 (`message`, `affected`) while anything uses the name. */
export function useDeleteVrf() {
  const qc = useQueryClient();
  return useMutation<unknown, Error, number>({
    mutationFn: (id) => detailRequest(`/ipam/vrfs/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateAll(qc),
  });
}

export function useCreateVlan() {
  const qc = useQueryClient();
  return useMutation<Vlan, Error, VlanCreate>({
    mutationFn: (data) => detailRequest<Vlan>('/ipam/vlans', { method: 'POST', body: data }),
    onSuccess: () => invalidateAll(qc),
  });
}

export function useUpdateVlan() {
  const qc = useQueryClient();
  return useMutation<Vlan, Error, { id: number; data: VlanUpdate }>({
    mutationFn: ({ id, data }) => detailRequest<Vlan>(`/ipam/vlans/${id}`, { method: 'PUT', body: data }),
    onSuccess: () => invalidateAll(qc),
  });
}

/** A VLAN that devices still carry is created again at their next collection. */
export function useDeleteVlan() {
  const qc = useQueryClient();
  return useMutation<unknown, Error, number>({
    mutationFn: (id) => detailRequest(`/ipam/vlans/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateAll(qc),
  });
}

/** Parses the newest stored configuration of every host again. */
export function useRebuildInterfaceAddresses() {
  const qc = useQueryClient();
  return useMutation<RebuildResult, Error, void>({
    mutationFn: () => detailRequest<RebuildResult>('/ipam/interface-addresses/rebuild', { method: 'POST' }),
    onSuccess: () => {
      invalidateAll(qc);
      qc.invalidateQueries({ queryKey: ['ipam-subnet-detail'] });
    },
  });
}
