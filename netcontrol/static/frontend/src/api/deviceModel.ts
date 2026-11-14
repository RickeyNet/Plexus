/**
 * Device model: the manufacturer, device type, role and lifecycle status
 * catalogues under /api/dcim, and bulk edit of those values (plus site and
 * rack / room) on hosts. Host rows carry the values inline (see
 * `InventoryHost`). Failures throw a `CustomDataError`: a 409 on delete
 * carries `affected`, a 400 on a host write names its `fields`.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import type { TagColor } from '@/lib/customData';

import { detailRequest, listOf } from './customData';
import { DEVICE_MODEL_QUERY_ROOT, type HostDeviceFields, invalidateInventory } from './inventory';

// ── Types ──────────────────────────────────────────────────────────────────

export interface Manufacturer {
  id: number;
  name: string;
  description: string;
  device_type_count: number;
  host_count: number;
}

export interface DeviceType {
  id: number;
  manufacturer_id: number;
  /** The manufacturer's name. */
  manufacturer: string;
  model: string;
  part_number: string;
  u_height: number;
  description: string;
  host_count: number;
}

export interface DeviceRole {
  id: number;
  name: string;
  color: TagColor | string;
  description: string;
  host_count: number;
}

export interface HostStatus {
  id: number;
  name: string;
  color: TagColor | string;
  description: string;
  is_default: boolean;
  host_count: number;
}

export interface ManufacturerInput {
  name: string;
  description: string;
}

export interface DeviceTypeInput {
  manufacturer_id: number;
  model: string;
  part_number: string;
  u_height: number;
  description: string;
}

export interface DeviceRoleInput {
  name: string;
  color: string;
  description: string;
}

export interface HostStatusInput extends DeviceRoleInput {
  is_default: boolean;
}

/** The `set` of a bulk edit: only the keys present are applied. */
export type BulkEditSet = HostDeviceFields;

export interface BulkEditResult {
  ok: boolean;
  updated: number;
}

// ── Query keys ─────────────────────────────────────────────────────────────

const ROOT = DEVICE_MODEL_QUERY_ROOT;
const KEYS = {
  manufacturers: [...ROOT, 'manufacturers'] as const,
  deviceTypes: (manufacturerId?: number) => [...ROOT, 'device-types', manufacturerId ?? 'all'] as const,
  roles: [...ROOT, 'roles'] as const,
  statuses: [...ROOT, 'statuses'] as const,
};

type QC = ReturnType<typeof useQueryClient>;

/** The catalogues (their host counts change too) and the host lists showing the values. */
function invalidateAll(qc: QC) {
  qc.invalidateQueries({ queryKey: ROOT });
  invalidateInventory(qc);
}

const byName = <T extends { name: string }>(rows: T[]) => [...rows].sort((a, b) => a.name.localeCompare(b.name));

// ── Queries ────────────────────────────────────────────────────────────────

export function useManufacturers() {
  return useQuery<Manufacturer[]>({
    queryKey: KEYS.manufacturers,
    queryFn: async () => byName(listOf<Manufacturer>(await detailRequest('/dcim/manufacturers'), 'manufacturers')),
  });
}

/** Device types, by manufacturer then model; with `manufacturerId`, only that manufacturer's. */
export function useDeviceTypes(manufacturerId?: number) {
  return useQuery<DeviceType[]>({
    queryKey: KEYS.deviceTypes(manufacturerId),
    queryFn: async () => {
      const qs = manufacturerId !== undefined ? `?manufacturer_id=${manufacturerId}` : '';
      const rows = listOf<DeviceType>(await detailRequest(`/dcim/device-types${qs}`), 'device_types');
      return rows.sort((a, b) => a.manufacturer.localeCompare(b.manufacturer) || a.model.localeCompare(b.model));
    },
  });
}

export function useDeviceRoles() {
  return useQuery<DeviceRole[]>({
    queryKey: KEYS.roles,
    queryFn: async () => byName(listOf<DeviceRole>(await detailRequest('/dcim/roles'), 'roles')),
  });
}

export function useHostStatuses() {
  return useQuery<HostStatus[]>({
    queryKey: KEYS.statuses,
    queryFn: async () => byName(listOf<HostStatus>(await detailRequest('/dcim/statuses'), 'statuses')),
  });
}

// ── Mutations: catalogues ──────────────────────────────────────────────────

/** `?confirm=true` when the caller confirmed a change that touches hosts. */
const confirmQs = (confirm?: boolean) => (confirm ? '?confirm=true' : '');

function useCreateRecord<T, I>(path: string) {
  const qc = useQueryClient();
  return useMutation<T, Error, I>({
    mutationFn: (data) => detailRequest<T>(path, { method: 'POST', body: data }),
    onSuccess: () => invalidateAll(qc),
  });
}

function useUpdateRecord<T, I>(path: string) {
  const qc = useQueryClient();
  return useMutation<T, Error, { id: number; data: I; confirm?: boolean }>({
    mutationFn: ({ id, data, confirm }) =>
      detailRequest<T>(`${path}/${id}${confirmQs(confirm)}`, { method: 'PUT', body: data }),
    onSuccess: () => invalidateAll(qc),
  });
}

/** Deletes a record. One in use is a 409 with `affected` (hosts) unless `confirm` is set. */
function useDeleteRecord(path: string) {
  const qc = useQueryClient();
  return useMutation<unknown, Error, { id: number; confirm?: boolean }>({
    mutationFn: ({ id, confirm }) => detailRequest(`${path}/${id}${confirmQs(confirm)}`, { method: 'DELETE' }),
    onSuccess: () => invalidateAll(qc),
  });
}

const MANUFACTURERS_PATH = '/dcim/manufacturers';
const DEVICE_TYPES_PATH = '/dcim/device-types';
const ROLES_PATH = '/dcim/roles';
const STATUSES_PATH = '/dcim/statuses';

export const useCreateManufacturer = () => useCreateRecord<Manufacturer, ManufacturerInput>(MANUFACTURERS_PATH);
export const useUpdateManufacturer = () => useUpdateRecord<Manufacturer, ManufacturerInput>(MANUFACTURERS_PATH);
/** Also deletes the manufacturer's device types; `affected` counts the hosts on all of them. */
export const useDeleteManufacturer = () => useDeleteRecord(MANUFACTURERS_PATH);

export const useCreateDeviceType = () => useCreateRecord<DeviceType, DeviceTypeInput>(DEVICE_TYPES_PATH);
export const useUpdateDeviceType = () => useUpdateRecord<DeviceType, DeviceTypeInput>(DEVICE_TYPES_PATH);
export const useDeleteDeviceType = () => useDeleteRecord(DEVICE_TYPES_PATH);

export const useCreateDeviceRole = () => useCreateRecord<DeviceRole, DeviceRoleInput>(ROLES_PATH);
export const useUpdateDeviceRole = () => useUpdateRecord<DeviceRole, DeviceRoleInput>(ROLES_PATH);
export const useDeleteDeviceRole = () => useDeleteRecord(ROLES_PATH);

/** Making a status the default clears the flag on the others (server side). */
export const useCreateHostStatus = () => useCreateRecord<HostStatus, HostStatusInput>(STATUSES_PATH);
export const useUpdateHostStatus = () => useUpdateRecord<HostStatus, HostStatusInput>(STATUSES_PATH);
/** The default status cannot be deleted. */
export const useDeleteHostStatus = () => useDeleteRecord(STATUSES_PATH);

// ── Mutations: hosts ───────────────────────────────────────────────────────

/** Sets the given device model values on many hosts (at most 5,000; unknown ids are skipped). */
export function useBulkEditHosts() {
  const qc = useQueryClient();
  return useMutation<BulkEditResult, Error, { hostIds: number[]; set: BulkEditSet }>({
    mutationFn: ({ hostIds, set }) =>
      detailRequest<BulkEditResult>('/hosts/bulk-edit', { method: 'POST', body: { host_ids: hostIds, set } }),
    onSuccess: () => {
      invalidateAll(qc);
      // Site host counts.
      qc.invalidateQueries({ queryKey: ['geo'] });
    },
  });
}
