/**
 * Virtualization under /api/virtualization (docs/virtualization.md): cluster
 * types, cluster groups, clusters with their hypervisor hosts, virtual
 * machines and their interfaces, and the cloud sync. Failures throw a
 * `CustomDataError`: a bad value is a 422 whose `fields` name the inputs, a
 * name already used or a delete refused while in use a 409.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { queryString } from './client';
import { detailRequest, listOf } from './customData';

// ── Types ──────────────────────────────────────────────────────────────────

/** `manual`: made or edited by a person; `discovered`: made by the cloud sync. */
export type VirtualizationOrigin = 'manual' | 'discovered';

export type VmStatus = 'active' | 'offline' | 'planned' | 'staged' | 'failed' | 'decommissioning';

export type InterfaceMode = '' | 'access' | 'tagged';

interface Stamps {
  created_by: string;
  created_at: string;
  updated_by: string;
  updated_at: string;
}

/** A cluster type or group. */
export interface ClusterCatalogItem extends Stamps {
  id: number;
  name: string;
  description: string;
  cluster_count: number;
}

export interface Cluster extends Stamps {
  id: number;
  name: string;
  cluster_type_id: number;
  cluster_type_name: string;
  cluster_group_id: number | null;
  cluster_group_name: string | null;
  site_id: number | null;
  site_name: string | null;
  tenant_id: number | null;
  tenant_name: string | null;
  description: string;
  comments: string;
  origin: VirtualizationOrigin | string;
  /** `provider:account id:region` of a cluster the cloud sync made, else ''. */
  cloud_key: string;
  host_count: number;
  vm_count: number;
}

export interface ClusterHost {
  id: number;
  hostname: string;
  ip_address: string;
  device_type: string;
  status: string;
  added_at: string;
  added_by: string;
}

export interface VirtualMachine extends Stamps {
  id: number;
  name: string;
  cluster_id: number;
  cluster_name: string;
  cluster_type_id: number;
  cluster_type_name: string;
  cluster_group_id: number | null;
  cluster_group_name: string | null;
  site_id: number | null;
  site_name: string | null;
  status: VmStatus | string;
  role_id: number | null;
  role_name: string | null;
  role_color: string | null;
  tenant_id: number | null;
  tenant_name: string | null;
  platform: string;
  vcpus: number | null;
  memory_mb: number | null;
  disk_gb: number | null;
  primary_ip4: string;
  primary_ip6: string;
  /** The discovered cloud instance the VM mirrors (null when unlinked or gone). */
  cloud_resource_id: number | null;
  cloud_account_id: number | null;
  cloud_resource_uid: string;
  cloud_provider: string | null;
  cloud_resource_type: string | null;
  cloud_resource_name: string | null;
  cloud_account_name: string | null;
  origin: VirtualizationOrigin | string;
  description: string;
  comments: string;
  interface_count: number;
}

export interface VmInterface extends Stamps {
  id: number;
  vm_id: number;
  name: string;
  enabled: boolean;
  mac_address: string;
  mtu: number | null;
  mode: InterfaceMode | string;
  untagged_vlan_id: number | null;
  untagged_vlan_vid: number | null;
  untagged_vlan_name: string | null;
  vrf_id: number | null;
  vrf_name: string | null;
  description: string;
  /** CIDR text, e.g. 192.0.2.10/24. */
  addresses: string[];
}

export interface ClusterDetail extends Cluster {
  hosts: ClusterHost[];
  virtual_machines: VirtualMachine[];
}

export interface VirtualMachineDetail extends VirtualMachine {
  interfaces: VmInterface[];
}

export interface CatalogInput {
  name?: string;
  description?: string;
}

export interface ClusterInput {
  name?: string;
  cluster_type_id?: number;
  cluster_group_id?: number | null;
  site_id?: number | null;
  tenant_id?: number | null;
  description?: string;
  comments?: string;
}

export interface VmInput {
  name?: string;
  cluster_id?: number;
  status?: string;
  role_id?: number | null;
  tenant_id?: number | null;
  platform?: string;
  vcpus?: number | null;
  memory_mb?: number | null;
  disk_gb?: number | null;
  primary_ip4?: string;
  primary_ip6?: string;
  description?: string;
  comments?: string;
}

export interface VmInterfaceInput {
  name?: string;
  enabled?: boolean;
  mac_address?: string;
  mtu?: number | null;
  mode?: string;
  untagged_vlan_id?: number | null;
  vrf_id?: number | null;
  description?: string;
  addresses?: string[];
}

export interface VmFilter {
  cluster_id?: number;
  cluster_type_id?: number;
  cluster_group_id?: number;
  site_id?: number;
  tenant_id?: number;
  role_id?: number;
  status?: string;
  origin?: string;
  search?: string;
}

export interface CloudSyncResult {
  ok: boolean;
  accounts: number;
  created: number;
  updated: number;
  unchanged: number;
  kept_manual: number;
  offline: number;
  skipped: number;
  failed: number;
}

export interface TenantChoice {
  id: number;
  name: string;
}

// ── Query keys ─────────────────────────────────────────────────────────────

export const VIRTUALIZATION_QUERY_ROOT = ['virtualization'] as const;
const ROOT = VIRTUALIZATION_QUERY_ROOT;
export const VIRTUALIZATION_KEYS = {
  types: [...ROOT, 'cluster-types'] as const,
  groups: [...ROOT, 'cluster-groups'] as const,
  clusters: [...ROOT, 'clusters'] as const,
  cluster: (id: number) => [...ROOT, 'cluster', id] as const,
  vms: (filter: VmFilter) => [...ROOT, 'vms', filter] as const,
  vm: (id: number) => [...ROOT, 'vm', id] as const,
  hostClusters: (hostId: number) => [...ROOT, 'host-clusters', hostId] as const,
  tenants: [...ROOT, 'tenants'] as const,
};

const BASE = '/virtualization';

type QC = ReturnType<typeof useQueryClient>;

/** Counts and names move together across every list and detail. */
function invalidateAll(qc: QC) {
  qc.invalidateQueries({ queryKey: ROOT });
}

// ── Queries ────────────────────────────────────────────────────────────────

export function useClusterTypes() {
  return useQuery<ClusterCatalogItem[]>({
    queryKey: VIRTUALIZATION_KEYS.types,
    queryFn: async ({ signal }) => listOf<ClusterCatalogItem>(await detailRequest(`${BASE}/cluster-types`, { signal }), 'cluster_types'),
  });
}

export function useClusterGroups() {
  return useQuery<ClusterCatalogItem[]>({
    queryKey: VIRTUALIZATION_KEYS.groups,
    queryFn: async ({ signal }) => listOf<ClusterCatalogItem>(await detailRequest(`${BASE}/cluster-groups`, { signal }), 'cluster_groups'),
  });
}

export function useClusters() {
  return useQuery<Cluster[]>({
    queryKey: VIRTUALIZATION_KEYS.clusters,
    queryFn: async ({ signal }) => listOf<Cluster>(await detailRequest(`${BASE}/clusters`, { signal }), 'clusters'),
  });
}

export function useCluster(id: number | null) {
  return useQuery<ClusterDetail>({
    queryKey: VIRTUALIZATION_KEYS.cluster(id ?? 0),
    queryFn: ({ signal }) => detailRequest<ClusterDetail>(`${BASE}/clusters/${id}`, { signal }),
    enabled: id !== null,
  });
}

export function useVirtualMachines(filter: VmFilter = {}) {
  return useQuery<VirtualMachine[]>({
    queryKey: VIRTUALIZATION_KEYS.vms(filter),
    queryFn: async ({ signal }) =>
      listOf<VirtualMachine>(await detailRequest(`${BASE}/virtual-machines${queryString(filter)}`, { signal }), 'virtual_machines'),
  });
}

export function useVirtualMachine(id: number | null) {
  return useQuery<VirtualMachineDetail>({
    queryKey: VIRTUALIZATION_KEYS.vm(id ?? 0),
    queryFn: ({ signal }) => detailRequest<VirtualMachineDetail>(`${BASE}/virtual-machines/${id}`, { signal }),
    enabled: id !== null,
  });
}

/** The clusters a host is a hypervisor of; `enabled` false for users without the feature. */
export function useHostClusters(hostId: number | null, enabled = true) {
  return useQuery<Cluster[]>({
    queryKey: VIRTUALIZATION_KEYS.hostClusters(hostId ?? 0),
    queryFn: async ({ signal }) => listOf<Cluster>(await detailRequest(`${BASE}/hosts/${hostId}/clusters`, { signal }), 'clusters'),
    enabled: enabled && hostId !== null,
  });
}

export function useTenantChoices() {
  return useQuery<TenantChoice[]>({
    queryKey: VIRTUALIZATION_KEYS.tenants,
    queryFn: async ({ signal }) => listOf<TenantChoice>(await detailRequest(`${BASE}/tenants`, { signal }), 'tenants'),
  });
}

// ── Mutations ──────────────────────────────────────────────────────────────

function useSave<T, I>(path: string) {
  const qc = useQueryClient();
  return useMutation<T, Error, { id: number | null; data: I }>({
    mutationFn: ({ id, data }) =>
      id === null
        ? detailRequest<T>(path, { method: 'POST', body: data })
        : detailRequest<T>(`${path}/${id}`, { method: 'PUT', body: data }),
    onSuccess: () => invalidateAll(qc),
  });
}

function useRemove(path: string) {
  const qc = useQueryClient();
  return useMutation<unknown, Error, number>({
    mutationFn: (id) => detailRequest(`${path}/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateAll(qc),
  });
}

/** `id` null creates. */
export const useSaveClusterType = () => useSave<ClusterCatalogItem, CatalogInput>(`${BASE}/cluster-types`);
/** Refused with a 409 while clusters have the type. */
export const useDeleteClusterType = () => useRemove(`${BASE}/cluster-types`);
export const useSaveClusterGroup = () => useSave<ClusterCatalogItem, CatalogInput>(`${BASE}/cluster-groups`);
/** Refused with a 409 while clusters are in the group. */
export const useDeleteClusterGroup = () => useRemove(`${BASE}/cluster-groups`);
export const useSaveCluster = () => useSave<Cluster, ClusterInput>(`${BASE}/clusters`);
/** Refused with a 409 while the cluster holds virtual machines. */
export const useDeleteCluster = () => useRemove(`${BASE}/clusters`);
/** Saving a VM makes it `manual`: the cloud sync stops changing it. */
export const useSaveVirtualMachine = () => useSave<VirtualMachine, VmInput>(`${BASE}/virtual-machines`);
export const useDeleteVirtualMachine = () => useRemove(`${BASE}/virtual-machines`);

export function useSaveVmInterface(vmId: number) {
  return useSave<VmInterface, VmInterfaceInput>(`${BASE}/virtual-machines/${vmId}/interfaces`);
}

export function useDeleteVmInterface(vmId: number) {
  return useRemove(`${BASE}/virtual-machines/${vmId}/interfaces`);
}

export function useAddClusterHost(clusterId: number) {
  const qc = useQueryClient();
  return useMutation<unknown, Error, number>({
    mutationFn: (hostId) =>
      detailRequest(`${BASE}/clusters/${clusterId}/hosts`, { method: 'POST', body: { host_id: hostId } }),
    onSuccess: () => invalidateAll(qc),
  });
}

export function useRemoveClusterHost(clusterId: number) {
  const qc = useQueryClient();
  return useMutation<unknown, Error, number>({
    mutationFn: (hostId) => detailRequest(`${BASE}/clusters/${clusterId}/hosts/${hostId}`, { method: 'DELETE' }),
    onSuccess: () => invalidateAll(qc),
  });
}

/** Admin: mirror the discovered AWS, Azure and GCP instances as VMs now. */
export function useSyncCloudVms() {
  const qc = useQueryClient();
  return useMutation<CloudSyncResult, Error, void>({
    mutationFn: () => detailRequest<CloudSyncResult>(`${BASE}/sync-cloud`, { method: 'POST', body: {} }),
    onSuccess: () => invalidateAll(qc),
  });
}
