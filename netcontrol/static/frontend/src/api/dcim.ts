/**
 * Physical DCIM under /api/dcim: rack roles, racks, reservations, patch panel
 * ports, modules, power panels / feeds / ports / outlets (one set of hooks
 * keyed by record kind), cables, cable traces, rack elevation and power, and
 * a device's placement. Failures throw a `CustomDataError`: a 422 carries a
 * message and per-field `fields`, a 409 a duplicate name, an endpoint that
 * already has a cable, or a delete of a record still in use.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { queryString } from './client';
import { detailRequest, listOf } from './customData';

// ── Types ──────────────────────────────────────────────────────────────────

export type DcimKind =
  | 'rack_role'
  | 'rack'
  | 'rack_reservation'
  | 'rear_port'
  | 'front_port'
  | 'module'
  | 'power_panel'
  | 'power_feed'
  | 'power_port'
  | 'power_outlet';

/** The API path segment of each record kind. */
export const DCIM_PATHS: Record<DcimKind, string> = {
  rack_role: 'rack-roles',
  rack: 'racks',
  rack_reservation: 'rack-reservations',
  rear_port: 'rear-ports',
  front_port: 'front-ports',
  module: 'modules',
  power_panel: 'power-panels',
  power_feed: 'power-feeds',
  power_port: 'power-ports',
  power_outlet: 'power-outlets',
};

/** A DCIM record as the API returns it: its columns plus display fields. */
export type DcimRecord = { id: number } & Record<string, unknown>;

export type EndpointType =
  'interface' | 'front_port' | 'rear_port' | 'circuit_termination' | 'power_port' | 'power_outlet' | 'power_feed';

export interface EndpointInput {
  type: EndpointType;
  id?: number | null;
  host_id?: number | null;
  name?: string;
}

/** A cable end or trace endpoint with its display fields. */
export interface Endpoint extends EndpointInput {
  host_name?: string;
  label?: string;
  missing?: boolean;
  power_panel_name?: string;
}

export interface Cable {
  id: number;
  a: Endpoint;
  b: Endpoint;
  status: string;
  type: string;
  label: string;
  color: string;
  length: number | null;
  length_unit: string;
  tenant_id: number | null;
  tenant_name: string | null;
  description: string;
}

export interface CableInput {
  a?: EndpointInput;
  b?: EndpointInput;
  status?: string;
  type?: string;
  label?: string;
  color?: string;
  length?: number | null;
  length_unit?: string;
  description?: string;
}

export type TraceStatus = 'complete' | 'dead_end' | 'unconnected' | 'missing' | 'ambiguous' | 'loop';

export interface TraceStep {
  kind: 'cable' | 'internal';
  near: Endpoint;
  far: Endpoint;
  cable?: {
    id: number;
    label?: string;
    type?: string;
    status?: string;
    color?: string;
  };
  position?: number | null;
}

export interface TraceResult {
  start: Endpoint;
  steps: TraceStep[];
  status: TraceStatus;
  is_loop: boolean;
  destination: Endpoint | null;
  power_panel?: { id: number; name: string } | null;
}

export interface ElevationBlock {
  kind: 'device' | 'reservation' | 'empty';
  units: number[];
  height: number;
  host_id?: number;
  name?: string;
  face?: string;
  mounted_here?: boolean;
  position?: number;
  reservation_id?: number;
  description?: string;
  user?: string;
}

export interface RackElevation {
  rack: DcimRecord;
  u_height: number;
  desc_units: boolean;
  units: number[];
  faces: { front: ElevationBlock[]; rear: ElevationBlock[] };
  unmounted: { host_id: number; name: string }[];
  used_units: number;
  free_units: number;
  reservations: DcimRecord[];
}

export interface FeedPower {
  id: number;
  name: string;
  type: string;
  status: string;
  available_power: number;
  allocated_draw: number;
  utilization: number | null;
}

export interface RackPower {
  feeds: FeedPower[];
  capacity: number;
  allocated_draw: number;
  unfed_draw: number;
  utilization: number | null;
  port_count: number;
  ports: {
    id: number;
    host_name: string;
    name: string;
    feed_name: string;
    allocated_draw: number | null;
    maximum_draw: number | null;
  }[];
}

export interface HostPlacement {
  host_id: number;
  hostname: string;
  site_id: number | null;
  rack_id: number | null;
  rack_position: number | null;
  rack_face: string;
  height: number;
  rack_name: string | null;
  rack_site_name: string | null;
}

export interface HostDcim {
  placement: HostPlacement;
  cables: Cable[];
  counts: Record<string, number>;
}

export interface DcimChoices {
  rack_statuses: string[];
  rack_widths: number[];
  faces: string[];
  port_types: string[];
  module_statuses: string[];
  feed_statuses: string[];
  feed_types: string[];
  feed_supplies: string[];
  feed_phases: string[];
  feed_legs: string[];
  cable_statuses: string[];
  cable_types: string[];
  length_units: string[];
  endpoint_types: string[];
}

// ── Queries ────────────────────────────────────────────────────────────────

const ROOT = ['dcim'] as const;

export type DcimFilters = Record<string, string | number | null | undefined>;

export function useDcimList(kind: DcimKind, filters: DcimFilters = {}, enabled = true) {
  return useQuery<DcimRecord[]>({
    queryKey: [...ROOT, kind, filters],
    queryFn: async () => listOf<DcimRecord>(await detailRequest(`/dcim/${DCIM_PATHS[kind]}${queryString(filters)}`), 'records'),
    enabled,
  });
}

export function useDcimChoices() {
  return useQuery<DcimChoices>({
    queryKey: [...ROOT, 'choices'],
    queryFn: () => detailRequest<DcimChoices>('/dcim/choices'),
    staleTime: Infinity,
  });
}

export function useRackElevation(rackId: number | null) {
  return useQuery<RackElevation>({
    queryKey: [...ROOT, 'elevation', rackId],
    queryFn: () => detailRequest<RackElevation>(`/dcim/racks/${rackId}/elevation`),
    enabled: rackId !== null,
  });
}

export function useRackPower(rackId: number | null) {
  return useQuery<RackPower>({
    queryKey: [...ROOT, 'rack-power', rackId],
    queryFn: () => detailRequest<RackPower>(`/dcim/racks/${rackId}/power`),
    enabled: rackId !== null,
  });
}

export function useCables(filters: DcimFilters = {}, enabled = true) {
  return useQuery<Cable[]>({
    queryKey: [...ROOT, 'cables', filters],
    queryFn: async () => listOf<Cable>(await detailRequest(`/dcim/cables${queryString(filters)}`), 'cables'),
    enabled,
  });
}

export function useTrace(endpoint: EndpointInput | null) {
  return useQuery<TraceResult>({
    queryKey: [...ROOT, 'trace', endpoint],
    queryFn: () => detailRequest<TraceResult>(`/dcim/trace${queryString(endpoint ?? {})}`),
    enabled: endpoint !== null,
  });
}

export function useHostDcim(hostId: number | null, enabled = true) {
  return useQuery<HostDcim>({
    queryKey: [...ROOT, 'host', hostId],
    queryFn: () => detailRequest<HostDcim>(`/dcim/hosts/${hostId}`),
    enabled: enabled && hostId !== null,
  });
}

export function useDcimHostInterfaces(hostId: number | null) {
  return useQuery<string[]>({
    queryKey: [...ROOT, 'host-interfaces', hostId],
    queryFn: async () => listOf<string>(await detailRequest(`/dcim/hosts/${hostId}/interfaces`), 'interfaces'),
    enabled: hostId !== null,
  });
}

// ── Mutations ──────────────────────────────────────────────────────────────

function useWrite<TBody, TResult = unknown>(request: (body: TBody) => Promise<TResult>) {
  const qc = useQueryClient();
  return useMutation<TResult, Error, TBody>({
    mutationFn: request,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ROOT });
      void qc.invalidateQueries({ queryKey: ['object-changes'] });
    },
  });
}

/** Creates (`id` null) or updates a record of `kind`. */
export function useSaveDcimRecord(kind: DcimKind) {
  return useWrite<{ id: number | null; data: Record<string, unknown> }, DcimRecord>(({ id, data }) =>
    detailRequest<DcimRecord>(id === null ? `/dcim/${DCIM_PATHS[kind]}` : `/dcim/${DCIM_PATHS[kind]}/${id}`, {
      method: id === null ? 'POST' : 'PUT',
      body: data,
    }),
  );
}

/** Refused with a 409 while the record is in use (devices in a rack, a cabled port...). */
export function useDeleteDcimRecord(kind: DcimKind) {
  return useWrite<number>((id) => detailRequest(`/dcim/${DCIM_PATHS[kind]}/${id}`, { method: 'DELETE' }));
}

export function useSaveCable() {
  return useWrite<{ id: number | null; data: CableInput }, Cable>(({ id, data }) =>
    detailRequest<Cable>(id === null ? '/dcim/cables' : `/dcim/cables/${id}`, {
      method: id === null ? 'POST' : 'PUT',
      body: data,
    }),
  );
}

export function useDeleteCable() {
  return useWrite<number>((id) => detailRequest(`/dcim/cables/${id}`, { method: 'DELETE' }));
}

/** Mounts a device (`rack_position`), moves it, or takes it out (`rack_id` null). */
export function usePlaceHost() {
  return useWrite<
    {
      hostId: number;
      rack_id?: number | null;
      rack_position?: number | null;
      rack_face?: string | null;
    },
    HostPlacement
  >(({ hostId, ...data }) =>
    detailRequest<HostPlacement>(`/dcim/hosts/${hostId}/placement`, {
      method: 'PUT',
      body: data,
    }),
  );
}
