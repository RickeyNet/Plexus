import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

// ── Types ───────────────────────────────────────────────────────────────────

export interface GeoFloor {
  id: number;
  site_id: number;
  name: string;
  floor_number?: number | null;
  image_filename?: string | null;
  placed_device_count?: number;
}

export interface GeoSiteSummary {
  id: number;
  name: string;
  address?: string | null;
  lat?: number | null;
  lng?: number | null;
  online_count: number;
  offline_count: number;
  unknown_count: number;
  placed_device_count: number;
  floor_count: number;
}

export interface GeoSite extends GeoSiteSummary {
  floors?: GeoFloor[];
}

export interface FloorPlacement {
  host_id: number;
  hostname: string;
  ip_address?: string | null;
  status?: string | null;
  x_pct: number;
  y_pct: number;
}

export interface InventoryGroup {
  id: number;
  name: string;
  hosts?: InventoryHost[];
}

export interface InventoryHost {
  id: number;
  hostname: string;
  ip_address?: string | null;
  status?: string | null;
  group_id?: number;
}

export interface SiteInput {
  name: string;
  address?: string;
  lat?: number | null;
  lng?: number | null;
}

export interface FloorInput {
  name: string;
  floor_number?: number | null;
}

// ── URL helpers ────────────────────────────────────────────────────────────

export function floorImageUrl(floorId: number, cacheBust?: number | string): string {
  const suffix = cacheBust !== undefined ? `?t=${cacheBust}` : '';
  return `/api/geo/floors/${floorId}/image${suffix}`;
}

// ── Queries ────────────────────────────────────────────────────────────────

export function useGeoOverview() {
  return useQuery({
    queryKey: ['geo', 'overview'],
    queryFn: () => apiRequest<GeoSiteSummary[]>('/geo/overview'),
  });
}

export function useGeoSite(siteId: number | null) {
  return useQuery({
    queryKey: ['geo', 'site', siteId],
    queryFn: () => apiRequest<GeoSite>(`/geo/sites/${siteId}`),
    enabled: siteId !== null,
  });
}

export function useGeoFloor(floorId: number | null) {
  return useQuery({
    queryKey: ['geo', 'floor', floorId],
    queryFn: () => apiRequest<GeoFloor>(`/geo/floors/${floorId}`),
    enabled: floorId !== null,
  });
}

export function useFloorPlacements(floorId: number | null) {
  return useQuery({
    queryKey: ['geo', 'floor', floorId, 'placements'],
    queryFn: () => apiRequest<FloorPlacement[]>(`/geo/floors/${floorId}/placements`),
    enabled: floorId !== null,
  });
}

export function useInventoryGroupsWithHosts(enabled: boolean) {
  return useQuery({
    queryKey: ['inventory', 'with-hosts'],
    queryFn: () =>
      apiRequest<InventoryGroup[]>('/inventory?include_hosts=true'),
    enabled,
  });
}

// ── Mutations ──────────────────────────────────────────────────────────────

function invalidateGeo(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: ['geo'] });
}

export function useCreateGeoSite() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: SiteInput) =>
      apiRequest<GeoSite>('/geo/sites', { method: 'POST', body }),
    onSuccess: () => invalidateGeo(qc),
  });
}

export function useCreateGeoFloor(siteId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: FloorInput) =>
      apiRequest<GeoFloor>(`/geo/sites/${siteId}/floors`, {
        method: 'POST',
        body,
      }),
    onSuccess: () => invalidateGeo(qc),
  });
}

export function useUpdateGeoFloor() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ floorId, body }: { floorId: number; body: FloorInput }) =>
      apiRequest<GeoFloor>(`/geo/floors/${floorId}`, { method: 'PUT', body }),
    onSuccess: () => invalidateGeo(qc),
  });
}

export function useDeleteGeoFloor() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (floorId: number) =>
      apiRequest<void>(`/geo/floors/${floorId}`, { method: 'DELETE' }),
    onSuccess: () => invalidateGeo(qc),
  });
}

export function useUploadFloorImage() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ floorId, file }: { floorId: number; file: File }) => {
      const form = new FormData();
      form.append('file', file);
      return apiRequest<unknown>(`/geo/floors/${floorId}/image`, {
        method: 'POST',
        body: form,
      });
    },
    onSuccess: () => invalidateGeo(qc),
  });
}

export function useUpsertFloorPlacement() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      floorId,
      hostId,
      x_pct,
      y_pct,
    }: {
      floorId: number;
      hostId: number;
      x_pct: number;
      y_pct: number;
    }) =>
      apiRequest<FloorPlacement>(
        `/geo/floors/${floorId}/placements/${hostId}`,
        { method: 'PUT', body: { x_pct, y_pct } },
      ),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({
        queryKey: ['geo', 'floor', vars.floorId, 'placements'],
      });
      qc.invalidateQueries({ queryKey: ['geo', 'overview'] });
    },
  });
}

export function useDeleteFloorPlacement() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ floorId, hostId }: { floorId: number; hostId: number }) =>
      apiRequest<void>(`/geo/floors/${floorId}/placements/${hostId}`, {
        method: 'DELETE',
      }),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({
        queryKey: ['geo', 'floor', vars.floorId, 'placements'],
      });
      qc.invalidateQueries({ queryKey: ['geo', 'overview'] });
    },
  });
}
