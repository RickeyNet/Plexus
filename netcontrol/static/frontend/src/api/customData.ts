/**
 * Custom fields and tags: admin-defined fields and tags on every object type
 * of the server's registry (hosts, groups, prefixes, VRFs, VLANs, sites,
 * circuits, racks...). Definitions live under /api/custom-fields and
 * /api/tags; an object's own tags and values under its `custom-data` route
 * (hosts, groups and prefixes keep their own; every other type uses
 * /api/objects/{type}/{id}/custom-data, which also carries its computed
 * fields and relationships). List endpoints carry the same data inline as
 * `tags` and `custom_fields` on each row.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import type { TagColor } from '@/lib/customData';

import { ApiError, apiRequest } from './client';
import { invalidateInventory } from './inventory';
import { invalidateOverview } from './ipam';

// ── Types ──────────────────────────────────────────────────────────────────

/** Every object type of the registry (`netcontrol.custom_fields.OBJECT_TYPE_SPECS`). */
export type ObjectType =
  | 'host'
  | 'group'
  | 'prefix'
  | 'vrf'
  | 'vlan'
  | 'region'
  | 'site'
  | 'tenant'
  | 'manufacturer'
  | 'device_type'
  | 'device_role'
  | 'circuit_provider'
  | 'circuit'
  | 'cluster'
  | 'virtual_machine'
  | 'autonomous_system'
  | 'bgp_peering'
  | 'rack'
  | 'cable';
/** The types addressed by id (every type but `prefix`). */
export type IdObjectType = Exclude<ObjectType, 'prefix'>;
export type Cardinality = 'one-to-one' | 'one-to-many' | 'many-to-many';
export type FieldType = 'text' | 'number' | 'boolean' | 'date' | 'url' | 'select';

export interface Tag {
  id: number;
  name: string;
  color: TagColor | string;
  description: string;
}

export interface TagWithUsage extends Tag {
  /** Assignments by object type: always host, group and prefix, then any other type in use. */
  usage: Partial<Record<ObjectType, number>>;
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

export type ObjectRef = { type: IdObjectType; id: number } | { type: 'prefix'; subnet: string; vrf?: string | null };

/** One related object, seen from the object whose panel lists it. */
export interface RelationshipLinkView {
  id: number;
  peer_id: number;
  /** Empty when the caller cannot read the peer's type. */
  peer_label: string;
}

/** A relationship the object's type takes part in, from one side, with its links. */
export interface RelationshipGroup {
  relationship: Relationship;
  side: 'source' | 'destination';
  peer_type: IdObjectType;
  links: RelationshipLinkView[];
}

/** What /api/objects/{type}/{id}/custom-data returns. */
export interface FullObjectData extends ObjectData {
  computed_fields: Record<string, string>;
  relationships: RelationshipGroup[];
}

export interface ObjectTypeInfo {
  key: ObjectType;
  label: string;
  /** Served by /api/objects/{type}/{id}/...; false for prefix. */
  generic: boolean;
  readable: boolean;
  writable: boolean;
}

export interface ComputedField {
  id: number;
  key: string;
  label: string;
  object_type: IdObjectType;
  template: string;
  description: string;
  sort_order: number;
}

export type ComputedFieldInput = Omit<ComputedField, 'id'>;

export interface Relationship {
  id: number;
  key: string;
  label: string;
  source_type: IdObjectType;
  destination_type: IdObjectType;
  cardinality: Cardinality;
  description: string;
  link_count?: number;
}

export type RelationshipInput = Omit<Relationship, 'id' | 'link_count'>;

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
 * the change would remove (`affected`), a template syntax error the line it
 * is on (`line`).
 */
export class CustomDataError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly fields: Record<string, string> = {},
    public readonly affected: number | null = null,
    public readonly line: number | null = null,
  ) {
    super(message);
    this.name = 'CustomDataError';
  }
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

/**
 * Turns an ApiError whose body carries `detail = {message, fields?, affected?,
 * line?}` into a CustomDataError; anything else is returned unchanged.
 */
export function toCustomDataError(err: unknown): unknown {
  if (!(err instanceof ApiError)) return err;
  const body = asRecord(err.body);
  const detail = asRecord(body?.detail) ?? asRecord(asRecord(body?.error)?.detail);
  const rawFields = asRecord(detail?.fields) ?? {};
  const fields: Record<string, string> = {};
  for (const [key, message] of Object.entries(rawFields)) fields[key] = String(message);
  const affected = typeof detail?.affected === 'number' ? detail.affected : null;
  const line = typeof detail?.line === 'number' ? detail.line : null;
  const message =
    (typeof detail?.message === 'string' && detail.message) ||
    (typeof asRecord(body?.error)?.message === 'string' && (asRecord(body?.error)?.message as string)) ||
    err.message;
  return new CustomDataError(message, err.status, fields, affected, line);
}

/** `apiRequest` whose failures carry the structured detail (see `toCustomDataError`). */
export async function detailRequest<T>(endpoint: string, options?: Parameters<typeof apiRequest>[1]): Promise<T> {
  try {
    return await apiRequest<T>(endpoint, options);
  } catch (err) {
    throw toCustomDataError(err);
  }
}

/** The list a catalogue endpoint returned, bare or wrapped as `{<key>: [...]}`. */
export function listOf<T>(body: unknown, key: string): T[] {
  if (Array.isArray(body)) return body as T[];
  const wrapped = asRecord(body)?.[key];
  return Array.isArray(wrapped) ? (wrapped as T[]) : [];
}

/** The generic object API base of an object: `/objects/{type}/{id}`. */
export function objectPath(type: IdObjectType, id: number): string {
  return `/objects/${type}/${id}`;
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
    default:
      return `${objectPath(ref.type, ref.id)}/custom-data`;
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
  full: (type: IdObjectType, id: number) => ['custom-data', 'object', 'full', `${type}:${id}`] as const,
  types: ['custom-data', 'types'] as const,
  computed: (objectType?: IdObjectType) => ['custom-data', 'computed', objectType ?? 'all'] as const,
  allComputed: ['custom-data', 'computed'] as const,
  relationships: (objectType?: IdObjectType) => ['custom-data', 'relationships', objectType ?? 'all'] as const,
  allRelationships: ['custom-data', 'relationships'] as const,
  lookup: (type: IdObjectType, q: string) => ['custom-data', 'lookup', type, q] as const,
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
    queryFn: async ({ signal }) => listOf<TagWithUsage>(await detailRequest('/tags', { signal }), 'tags'),
  });
}

/** Field definitions, in display order; with `objectType`, only those that apply to it. */
export function useCustomFields(objectType?: ObjectType) {
  return useQuery<CustomField[]>({
    queryKey: KEYS.fields(objectType),
    queryFn: async ({ signal }) => {
      const qs = objectType ? `?object_type=${objectType}` : '';
      return listOf<CustomField>(await detailRequest(`/custom-fields${qs}`, { signal }), 'fields');
    },
  });
}

export function useObjectData(ref: ObjectRef | null, enabled = true) {
  return useQuery<ObjectData>({
    queryKey: ref ? KEYS.object(ref) : [...KEYS.allObjects, 'none'],
    queryFn: ({ signal }) => detailRequest<ObjectData>(objectDataPath(ref!), { signal }),
    enabled: enabled && ref != null,
  });
}

// ── Mutations: object data ─────────────────────────────────────────────────

/** Replaces an object's tags and values. A 400 throws a CustomDataError with `fields`. */
export function useSaveObjectData() {
  const qc = useQueryClient();
  return useMutation<ObjectData, Error, { ref: ObjectRef; data: ObjectDataPut }>({
    mutationFn: ({ ref, data }) => detailRequest<ObjectData>(objectDataPath(ref), { method: 'PUT', body: data }),
    onSuccess: (_saved, { ref }) => {
      qc.invalidateQueries({ queryKey: KEYS.object(ref) });
      qc.invalidateQueries({ queryKey: KEYS.tags });
      if (ref.type === 'prefix') invalidateOverview(qc);
      else if (ref.type === 'host' || ref.type === 'group') invalidateInventory(qc);
      else qc.invalidateQueries({ queryKey: KEYS.full(ref.type, ref.id) });
    },
  });
}

export function useBulkTagHosts() {
  const qc = useQueryClient();
  return useMutation<unknown, Error, { hostIds: number[]; addTagIds: number[]; removeTagIds: number[] }>({
    mutationFn: ({ hostIds, addTagIds, removeTagIds }) =>
      detailRequest('/hosts/bulk-tags', {
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
      detailRequest<Tag>('/tags', {
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
    mutationFn: ({ id, data }) => detailRequest<Tag>(`/tags/${id}`, { method: 'PUT', body: data }),
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
    mutationFn: (id) => detailRequest(`/tags/${id}`, { method: 'DELETE' }),
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
    mutationFn: (data) => detailRequest<CustomField>('/custom-fields', { method: 'POST', body: data }),
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
      detailRequest<CustomField>(`/custom-fields/${id}${confirm ? '?confirm=true' : ''}`, { method: 'PUT', body: data }),
    onSuccess: () => invalidateFields(qc),
  });
}

export function useDeleteCustomField() {
  const qc = useQueryClient();
  return useMutation<{ ok: boolean; removed: number }, Error, number>({
    mutationFn: (id) => detailRequest(`/custom-fields/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateFields(qc),
  });
}

// ── Every object type: catalogue, full data, relationships ─────────────────

/** The object types that carry custom data, with whether the caller reads and changes each. */
export function useObjectTypes() {
  return useQuery<ObjectTypeInfo[]>({
    queryKey: KEYS.types,
    queryFn: ({ signal }) => detailRequest<ObjectTypeInfo[]>('/custom-object-types', { signal }),
    staleTime: 5 * 60_000,
  });
}

/** An object's tags, values, computed fields and relationships (generic object API). */
export function useFullObjectData(type: IdObjectType, id: number | null) {
  return useQuery<FullObjectData>({
    queryKey: id === null ? [...KEYS.allObjects, 'full', 'none'] : KEYS.full(type, id),
    queryFn: ({ signal }) => detailRequest<FullObjectData>(`${objectPath(type, id!)}/custom-data`, { signal }),
    enabled: id !== null,
  });
}

/** Up to 50 objects of a type whose name contains `q`: the relationship picker. */
export function useObjectLookup(type: IdObjectType | null, q: string) {
  return useQuery<{ id: number; label: string }[]>({
    queryKey: KEYS.lookup(type ?? 'host', q),
    queryFn: ({ signal }) => detailRequest(`/objects/${type}/lookup?q=${encodeURIComponent(q)}`, { signal }),
    enabled: type !== null,
    staleTime: 30_000,
  });
}

function invalidateObjectData(qc: QC) {
  qc.invalidateQueries({ queryKey: KEYS.allObjects });
  qc.invalidateQueries({ queryKey: KEYS.allRelationships });
}

/** Links the object to `peerId`. A link the cardinality forbids is a 409. */
export function useAddObjectLink(type: IdObjectType, id: number) {
  const qc = useQueryClient();
  return useMutation<unknown, Error, { relationshipId: number; peerId: number; side?: 'source' | 'destination' }>({
    mutationFn: ({ relationshipId, peerId, side }) =>
      detailRequest(`${objectPath(type, id)}/relationships`, {
        method: 'POST',
        body: { relationship_id: relationshipId, peer_id: peerId, ...(side ? { side } : {}) },
      }),
    onSuccess: () => invalidateObjectData(qc),
  });
}

export function useDeleteObjectLink(type: IdObjectType, id: number) {
  const qc = useQueryClient();
  return useMutation<unknown, Error, number>({
    mutationFn: (linkId) => detailRequest(`${objectPath(type, id)}/relationships/${linkId}`, { method: 'DELETE' }),
    onSuccess: () => invalidateObjectData(qc),
  });
}

// ── Computed field and relationship definitions ────────────────────────────

export function useComputedFields(objectType?: IdObjectType) {
  return useQuery<ComputedField[]>({
    queryKey: KEYS.computed(objectType),
    queryFn: ({ signal }) => detailRequest<ComputedField[]>(`/computed-fields${objectType ? `?object_type=${objectType}` : ''}`, { signal }),
  });
}

function invalidateComputed(qc: QC) {
  qc.invalidateQueries({ queryKey: KEYS.allComputed });
  qc.invalidateQueries({ queryKey: KEYS.allObjects });
}

/** Creates (no `id`) or updates a computed field. A template syntax error is a 422. */
export function useSaveComputedField() {
  const qc = useQueryClient();
  return useMutation<ComputedField, Error, { id?: number; data: ComputedFieldInput }>({
    mutationFn: ({ id, data }) =>
      id === undefined
        ? detailRequest<ComputedField>('/computed-fields', { method: 'POST', body: data })
        : detailRequest<ComputedField>(`/computed-fields/${id}`, {
            method: 'PUT',
            body: { label: data.label, template: data.template, description: data.description, sort_order: data.sort_order },
          }),
    onSuccess: () => invalidateComputed(qc),
  });
}

export function useDeleteComputedField() {
  const qc = useQueryClient();
  return useMutation<unknown, Error, number>({
    mutationFn: (id) => detailRequest(`/computed-fields/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateComputed(qc),
  });
}

/** Renders a template against one object: `{value, error}`. */
export function usePreviewComputedField() {
  return useMutation<{ value: string; error: string | null }, Error, { object_type: IdObjectType; object_id: number; template: string }>({
    mutationFn: (body) => detailRequest('/computed-fields/preview', { method: 'POST', body }),
  });
}

export function useRelationships(objectType?: IdObjectType) {
  return useQuery<Relationship[]>({
    queryKey: KEYS.relationships(objectType),
    queryFn: ({ signal }) => detailRequest<Relationship[]>(`/relationships${objectType ? `?object_type=${objectType}` : ''}`, { signal }),
  });
}

/** Creates (no `id`) or updates a relationship; only the label and description change on update. */
export function useSaveRelationship() {
  const qc = useQueryClient();
  return useMutation<Relationship, Error, { id?: number; data: RelationshipInput }>({
    mutationFn: ({ id, data }) =>
      id === undefined
        ? detailRequest<Relationship>('/relationships', { method: 'POST', body: data })
        : detailRequest<Relationship>(`/relationships/${id}`, {
            method: 'PUT',
            body: { label: data.label, description: data.description },
          }),
    onSuccess: () => invalidateObjectData(qc),
  });
}

export function useDeleteRelationship() {
  const qc = useQueryClient();
  return useMutation<{ ok: boolean; removed: number }, Error, number>({
    mutationFn: (id) => detailRequest(`/relationships/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidateObjectData(qc),
  });
}
