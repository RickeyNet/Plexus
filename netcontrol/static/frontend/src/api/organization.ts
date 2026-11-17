/**
 * Regions, the location tree, tenant groups and tenants under
 * /api/organization (read: the `organization` feature; writes: admins).
 * Sites are written through /api/geo/sites (see `useSaveSite`). Failures
 * throw a `CustomDataError`: a 422 names its fields (a bad name, a parent
 * that would make a cycle), a 409 says a name is taken or a region still
 * holds regions or sites.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { detailRequest, listOf } from './customData';
import type { SiteInput } from './floorPlan';

// ── Types ──────────────────────────────────────────────────────────────────

interface Stamped {
  created_by: string;
  created_at: string;
  updated_by: string;
  updated_at: string;
}

/** A node of a tree catalogue (regions, tenant groups), listed in tree order. */
export interface TreeNode extends Stamped {
  id: number;
  parent_id: number | null;
  name: string;
  description: string;
  /** Names from the top, joined with " / ". */
  path: string;
  /** 0 for a top-level node. */
  depth: number;
  child_count: number;
}

export interface Region extends TreeNode {
  /** Sites directly in the region. */
  site_count: number;
  /** Sites in the region and every region under it. */
  total_site_count: number;
}

export interface TenantGroup extends TreeNode {
  tenant_count: number;
  total_tenant_count: number;
}

export interface Tenant extends Stamped {
  id: number;
  name: string;
  group_id: number | null;
  group_name: string | null;
  description: string;
  comments: string;
}

/** Rows the tenant owns per kind: hosts, prefixes, ip_addresses, vlans, vrfs, sites, and any later kind. */
export type TenantCounts = Record<string, number>;

export interface TenantDetail extends Tenant {
  counts: TenantCounts;
}

export const SITE_STATUSES = ['active', 'planned', 'staging', 'decommissioning', 'retired'] as const;
export type SiteStatus = (typeof SITE_STATUSES)[number];

/** A site as the organization endpoints list it. */
export interface OrgSite {
  id: number;
  name: string;
  description?: string | null;
  address?: string | null;
  lat?: number | null;
  lng?: number | null;
  region_id: number | null;
  region_name?: string | null;
  status: SiteStatus | string;
  facility: string;
  time_zone: string;
  tenant_id: number | null;
  tenant_name?: string | null;
  host_count?: number | null;
  floor_count?: number | null;
}

export interface LocationFloor {
  id: number;
  name: string;
  floor_number: number | null;
  placed_device_count: number;
}

export interface LocationSite {
  id: number;
  name: string;
  region_id: number | null;
  status: string;
  facility: string;
  time_zone: string;
  tenant_id: number | null;
  tenant_name: string | null;
  host_count: number;
  floors: LocationFloor[];
}

export interface LocationRegion extends Region {
  /** Hosts of its sites and of its descendants' sites. */
  host_count: number;
  sites: LocationSite[];
  children: LocationRegion[];
}

export interface LocationTree {
  regions: LocationRegion[];
  unassigned_sites: LocationSite[];
}

export interface TreeNodeInput {
  name?: string;
  parent_id?: number | null;
  description?: string;
}

export interface TenantInput {
  name?: string;
  group_id?: number | null;
  description?: string;
  comments?: string;
}


// ── Query keys ─────────────────────────────────────────────────────────────

export const ORGANIZATION_QUERY_ROOT = ['organization'] as const;
const ROOT = ORGANIZATION_QUERY_ROOT;
export const ORGANIZATION_KEYS = {
  regions: [...ROOT, 'regions'] as const,
  locations: [...ROOT, 'locations'] as const,
  sites: [...ROOT, 'sites'] as const,
  tenantGroups: [...ROOT, 'tenant-groups'] as const,
  tenants: [...ROOT, 'tenants'] as const,
  tenant: (id: number) => [...ROOT, 'tenant', id] as const,
};

type QC = ReturnType<typeof useQueryClient>;

/** Counts move together (sites per region, tenants per group), so every answer refreshes. */
function invalidateAll(qc: QC) {
  qc.invalidateQueries({ queryKey: ROOT });
  qc.invalidateQueries({ queryKey: ['geo'] });
}

// ── Queries ────────────────────────────────────────────────────────────────

/** Every region in tree order. */
export function useRegions(enabled = true) {
  return useQuery<Region[]>({
    queryKey: ORGANIZATION_KEYS.regions,
    queryFn: async () => listOf<Region>(await detailRequest('/organization/regions'), 'regions'),
    enabled,
    // A caller without the organization feature gets a 403; the filter menus just offer no regions.
    retry: false,
  });
}

export function useLocationTree() {
  return useQuery<LocationTree>({
    queryKey: ORGANIZATION_KEYS.locations,
    queryFn: () => detailRequest<LocationTree>('/organization/locations'),
  });
}

export function useOrgSites() {
  return useQuery<OrgSite[]>({
    queryKey: ORGANIZATION_KEYS.sites,
    queryFn: async () => listOf<OrgSite>(await detailRequest('/organization/sites'), 'sites'),
  });
}

export function useTenantGroups() {
  return useQuery<TenantGroup[]>({
    queryKey: ORGANIZATION_KEYS.tenantGroups,
    queryFn: async () => listOf<TenantGroup>(await detailRequest('/organization/tenant-groups'), 'tenant_groups'),
  });
}

/** Every tenant by name. `enabled` false skips the request (a caller without the feature). */
export function useTenants(enabled = true) {
  return useQuery<Tenant[]>({
    queryKey: ORGANIZATION_KEYS.tenants,
    queryFn: async () => listOf<Tenant>(await detailRequest('/organization/tenants'), 'tenants'),
    enabled,
    retry: false,
  });
}

export function useTenant(id: number | null) {
  return useQuery<TenantDetail>({
    queryKey: ORGANIZATION_KEYS.tenant(id ?? 0),
    queryFn: () => detailRequest<TenantDetail>(`/organization/tenants/${id}`),
    enabled: id !== null,
  });
}

// ── Mutations (admin) ──────────────────────────────────────────────────────

type Kind = 'regions' | 'tenant-groups' | 'tenants';

function useSave<T, I>(kind: Kind) {
  const qc = useQueryClient();
  return useMutation<T, Error, { id: number | null; data: I }>({
    mutationFn: ({ id, data }) =>
      detailRequest<T>(id === null ? `/organization/${kind}` : `/organization/${kind}/${id}`, {
        method: id === null ? 'POST' : 'PUT',
        body: data,
      }),
    onSuccess: () => invalidateAll(qc),
  });
}

function useRemove(kind: Kind) {
  const qc = useQueryClient();
  return useMutation<unknown, Error, number>({
    mutationFn: (id) => detailRequest(`/organization/${kind}/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateAll(qc),
  });
}

/** Creates (`id` null) or updates a region. */
export const useSaveRegion = () => useSave<Region, TreeNodeInput>('regions');
/** Refused with a 409 while the region holds regions or sites. */
export const useDeleteRegion = () => useRemove('regions');
export const useSaveTenantGroup = () => useSave<TenantGroup, TreeNodeInput>('tenant-groups');
/** Refused with a 409 while the group has child groups; its tenants are left in no group. */
export const useDeleteTenantGroup = () => useRemove('tenant-groups');
export const useSaveTenant = () => useSave<Tenant, TenantInput>('tenants');
/** What the tenant owned stays, with no tenant. */
export const useDeleteTenant = () => useRemove('tenants');

/** Creates (`id` null) or updates a site through /api/geo/sites. */
export function useSaveSite() {
  const qc = useQueryClient();
  return useMutation<OrgSite, Error, { id: number | null; data: SiteInput }>({
    mutationFn: ({ id, data }) =>
      detailRequest<OrgSite>(id === null ? '/geo/sites' : `/geo/sites/${id}`, {
        method: id === null ? 'POST' : 'PUT',
        body: data,
      }),
    onSuccess: () => invalidateAll(qc),
  });
}

export function useDeleteSite() {
  const qc = useQueryClient();
  return useMutation<unknown, Error, number>({
    mutationFn: (id) => detailRequest(`/geo/sites/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateAll(qc),
  });
}

/** Sets or clears the tenant of an IPAM prefix or allocation (admin). */
export function useSetIpamTenant() {
  const qc = useQueryClient();
  return useMutation<unknown, Error, { kind: 'prefixes' | 'allocations'; id: number; tenantId: number | null }>({
    mutationFn: ({ kind, id, tenantId }) =>
      detailRequest(`/ipam/${kind}/${id}`, { method: 'PATCH', body: { tenant_id: tenantId } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ipam-subnet-detail'] });
      qc.invalidateQueries({ queryKey: ROOT });
    },
  });
}
