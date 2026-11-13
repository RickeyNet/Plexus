/**
 * Custom fields and tags: admin-defined fields and tags on hosts, inventory
 * groups and IPAM prefixes. Definitions live under /api/custom-fields and
 * /api/tags; an object's own tags and values under its `custom-data` route.
 * List endpoints (inventory, IPAM overview) carry the same data inline as
 * `tags` and `custom_fields` on each row.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import type { TagColor } from '@/lib/customData';

import { ApiError, apiRequest } from './client';
import { invalidateInventory } from './inventory';
import { invalidateOverview } from './ipam';

// ── Types ──────────────────────────────────────────────────────────────────

export type ObjectType = 'host' | 'group' | 'prefix';
export type FieldType = 'text' | 'number' | 'boolean' | 'date' | 'url' | 'select';

export interface Tag {
  id: number;
  name: string;
  color: TagColor | string;
  description: string;
}

export interface TagWithUsage extends Tag {
  usage: Record<ObjectType, number>;
}

export interface TagRef {
  id: number;
  name: string;
  color: TagColor | string;
}

export interface CustomField {
  id: number;
  key: string;
  label: string;
  field_type: FieldType;
  choices: string[];
  object_types: ObjectType[];
  required: boolean;
  default_value: string;
  description: string;
  sort_order: number;
  /** Objects holding a value for the field, when the server reports it. */
  value_count?: number;
}

/** A stored value: `number` fields as numbers, `boolean` as booleans, the rest as strings. */
export type CustomValue = string | number | boolean;

export interface ObjectData {
  tags: TagRef[];
  fields: Record<string, CustomValue>;
}

/** A full replace: tags become exactly `tag_ids`; a field absent, null or '' is cleared. */
export interface ObjectDataPut {
  tag_ids: number[];
  fields: Record<string, CustomValue | null>;
}

export type ObjectRef =
  | { type: 'host'; id: number }
  | { type: 'group'; id: number }
  | { type: 'prefix'; subnet: string; vrf?: string | null };

/** The editable part of a field definition (`key` and `field_type` only count on create). */
export interface CustomFieldInput {
  key: string;
  label: string;
  field_type: FieldType;
  choices: string[];
  object_types: ObjectType[];
  required: boolean;
  default_value: string;
  description: string;
  sort_order: number;
}

export interface TagInput {
  name: string;
  color: TagColor | string;
  description: string;
}

/**
 * A failed custom-data request with what the server said: a 400 names the
 * fields it rejected (`fields`), a 409 on a field update the number of values
 * the change would remove (`affected`).
 */
export class CustomDataError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly fields: Record<string, string> = {},
    public readonly affected: number | null = null,
  ) {
    super(message);
    this.name = 'CustomDataError';
  }
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

/**
 * Turns an ApiError whose body carries `detail = {message, fields?, affected?}`
 * into a CustomDataError; anything else is returned unchanged.
 */
export function toCustomDataError(err: unknown): unknown {
  if (!(err instanceof ApiError)) return err;
  const body = asRecord(err.body);
  const detail = asRecord(body?.detail) ?? asRecord(asRecord(body?.error)?.detail);
  const rawFields = asRecord(detail?.fields) ?? {};
  const fields: Record<string, string> = {};
  for (const [key, message] of Object.entries(rawFields)) fields[key] = String(message);
  const affected = typeof detail?.affected === 'number' ? detail.affected : null;
  const message =
    (typeof detail?.message === 'string' && detail.message) ||
    (typeof asRecord(body?.error)?.message === 'string' && (asRecord(body?.error)?.message as string)) ||
    err.message;
  return new CustomDataError(message, err.status, fields, affected);
}

async function request<T>(endpoint: string, options?: Parameters<typeof apiRequest>[1]): Promise<T> {
  try {
    return await apiRequest<T>(endpoint, options);
  } catch (err) {
    throw toCustomDataError(err);
  }
}

/** The list a definitions endpoint returned, bare or wrapped as `{<key>: [...]}`. */
function listOf<T>(body: unknown, key: string): T[] {
  if (Array.isArray(body)) return body as T[];
  const wrapped = asRecord(body)?.[key];
  return Array.isArray(wrapped) ? (wrapped as T[]) : [];
}

/** The custom-data URL of an object. */
export function objectDataPath(ref: ObjectRef): string {
  switch (ref.type) {
    case 'host':
      return `/hosts/${ref.id}/custom-data`;
    case 'group':
      return `/inventory/${ref.id}/custom-data`;
    case 'prefix': {
      const qs = new URLSearchParams({ subnet: ref.subnet, vrf: ref.vrf ?? '' });
      return `/ipam/prefix-custom-data?${qs.toString()}`;
    }
  }
}

function refKey(ref: ObjectRef): string {
  return ref.type === 'prefix' ? `prefix:${ref.subnet}|${ref.vrf ?? ''}` : `${ref.type}:${ref.id}`;
}

// ── Query keys ─────────────────────────────────────────────────────────────

const KEYS = {
  all: ['custom-data'] as const,
  tags: ['custom-data', 'tags'] as const,
  fields: (objectType?: ObjectType) => ['custom-data', 'fields', objectType ?? 'all'] as const,
  allFields: ['custom-data', 'fields'] as const,
  object: (ref: ObjectRef) => ['custom-data', 'object', refKey(ref)] as const,
  allObjects: ['custom-data', 'object'] as const,
};

type QC = ReturnType<typeof useQueryClient>;

/** The lists that show tags and values inline. */
function invalidateLists(qc: QC) {
  invalidateInventory(qc);
  invalidateOverview(qc);
}

// ── Queries ────────────────────────────────────────────────────────────────

export function useTags() {
  return useQuery<TagWithUsage[]>({
    queryKey: KEYS.tags,
    queryFn: async () => listOf<TagWithUsage>(await request('/tags'), 'tags'),
  });
}

/** Field definitions, in display order; with `objectType`, only those that apply to it. */
export function useCustomFields(objectType?: ObjectType) {
  return useQuery<CustomField[]>({
    queryKey: KEYS.fields(objectType),
    queryFn: async () => {
      const qs = objectType ? `?object_type=${objectType}` : '';
      return listOf<CustomField>(await request(`/custom-fields${qs}`), 'fields');
    },
  });
}

export function useObjectData(ref: ObjectRef | null, enabled = true) {
  return useQuery<ObjectData>({
    queryKey: ref ? KEYS.object(ref) : [...KEYS.allObjects, 'none'],
    queryFn: () => request<ObjectData>(objectDataPath(ref!)),
    enabled: enabled && ref != null,
  });
}

// ── Mutations: object data ─────────────────────────────────────────────────

/** Replaces an object's tags and values. A 400 throws a CustomDataError with `fields`. */
export function useSaveObjectData() {
  const qc = useQueryClient();
  return useMutation<ObjectData, Error, { ref: ObjectRef; data: ObjectDataPut }>({
    mutationFn: ({ ref, data }) => request<ObjectData>(objectDataPath(ref), { method: 'PUT', body: data }),
    onSuccess: (_saved, { ref }) => {
      qc.invalidateQueries({ queryKey: KEYS.object(ref) });
      qc.invalidateQueries({ queryKey: KEYS.tags });
      if (ref.type === 'prefix') invalidateOverview(qc);
      else invalidateInventory(qc);
    },
  });
}

export function useBulkTagHosts() {
  const qc = useQueryClient();
  return useMutation<unknown, Error, { hostIds: number[]; addTagIds: number[]; removeTagIds: number[] }>({
    mutationFn: ({ hostIds, addTagIds, removeTagIds }) =>
      request('/hosts/bulk-tags', {
        method: 'POST',
        body: { host_ids: hostIds, add_tag_ids: addTagIds, remove_tag_ids: removeTagIds },
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: KEYS.tags });
      qc.invalidateQueries({ queryKey: KEYS.allObjects });
      invalidateInventory(qc);
    },
  });
}

// ── Mutations: tags ────────────────────────────────────────────────────────

/** Creates a tag; the new tag is in the `useTags()` list at once. A taken name is a 409. */
export function useCreateTag() {
  const qc = useQueryClient();
  return useMutation<Tag, Error, Partial<TagInput> & { name: string }>({
    mutationFn: (input) =>
      request<Tag>('/tags', {
        method: 'POST',
        body: { color: 'gray', description: '', ...input },
      }),
    onSuccess: (tag) => {
      qc.setQueryData<TagWithUsage[]>(KEYS.tags, (old) =>
        old && !old.some((t) => t.id === tag.id)
          ? [...old, { ...tag, usage: { host: 0, group: 0, prefix: 0 } }]
          : old,
      );
      qc.invalidateQueries({ queryKey: KEYS.tags });
    },
  });
}

export function useUpdateTag() {
  const qc = useQueryClient();
  return useMutation<Tag, Error, { id: number; data: TagInput }>({
    mutationFn: ({ id, data }) => request<Tag>(`/tags/${id}`, { method: 'PUT', body: data }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: KEYS.tags });
      qc.invalidateQueries({ queryKey: KEYS.allObjects });
      invalidateLists(qc);
    },
  });
}

export function useDeleteTag() {
  const qc = useQueryClient();
  return useMutation<{ ok: boolean; removed: number }, Error, number>({
    mutationFn: (id) => request(`/tags/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: KEYS.tags });
      qc.invalidateQueries({ queryKey: KEYS.allObjects });
      invalidateLists(qc);
    },
  });
}

// ── Mutations: field definitions ───────────────────────────────────────────

function invalidateFields(qc: QC) {
  qc.invalidateQueries({ queryKey: KEYS.allFields });
  qc.invalidateQueries({ queryKey: KEYS.allObjects });
  invalidateLists(qc);
}

/** Creates a field. A taken key is a 409. */
export function useCreateCustomField() {
  const qc = useQueryClient();
  return useMutation<CustomField, Error, CustomFieldInput>({
    mutationFn: (data) => request<CustomField>('/custom-fields', { method: 'POST', body: data }),
    onSuccess: () => invalidateFields(qc),
  });
}

/**
 * Updates a field (`key` and `field_type` are ignored by the server). A change
 * that removes object types holding values is a 409 with `affected` unless
 * `confirm` is set.
 */
export function useUpdateCustomField() {
  const qc = useQueryClient();
  return useMutation<CustomField, Error, { id: number; data: Omit<CustomFieldInput, 'key' | 'field_type'>; confirm?: boolean }>({
    mutationFn: ({ id, data, confirm }) =>
      request<CustomField>(`/custom-fields/${id}${confirm ? '?confirm=true' : ''}`, { method: 'PUT', body: data }),
    onSuccess: () => invalidateFields(qc),
  });
}

export function useDeleteCustomField() {
  const qc = useQueryClient();
  return useMutation<{ ok: boolean; removed: number }, Error, number>({
    mutationFn: (id) => request(`/custom-fields/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateFields(qc),
  });
}
