// Dynamic group filter definitions (the `filter` of /api/dynamic-groups)
// and the form state of the filter builder. Tags, custom fields and the
// device model facets use the inventory Filter menu's own value
// (`CustomDataFilterValue`), so a filter set on the Inventory page converts
// to a dynamic group as it stands. The server validates and resolves.

import { type CustomDataFilterValue, EMPTY_CUSTOM_DATA_FILTER, HAS_VALUE } from './customData';
import { DEVICE_FACETS, type DeviceFacet, type DeviceFilterValue, type FacetChoice, NONE } from './deviceModel';

export type SearchMode = 'contains' | 'regex';
export type TagMatch = 'any' | 'all';

/** The device model keys of a definition: ids, `null` for "no value". */
export type DeviceKey =
  | 'manufacturer_id'
  | 'device_type_id'
  | 'role_id'
  | 'lifecycle_status_id'
  | 'site_id'
  | 'region_id'
  | 'tenant_id';

export const FACET_KEYS: Record<DeviceFacet, DeviceKey> = {
  manufacturer: 'manufacturer_id',
  device_type: 'device_type_id',
  role: 'role_id',
  lifecycle_status: 'lifecycle_status_id',
  site: 'site_id',
  // A region matches the hosts of its sites and of every region under it.
  region: 'region_id',
  tenant: 'tenant_id',
};

/** The wire format; every criterion is optional and criteria combine with AND. */
export interface DynamicGroupFilter extends Partial<Record<DeviceKey, (number | null)[]>> {
  groups?: number[];
  include_subgroups?: boolean;
  platforms?: string[];
  statuses?: string[];
  tag_ids?: number[];
  tag_match?: TagMatch;
  /** Field key to accepted values; `*` accepts any value. */
  custom_fields?: Record<string, string[]>;
  search?: { mode: SearchMode; value: string };
  prefixes?: string[];
}

/** Reachability statuses a host can have. */
export const HOST_STATUSES = ['up', 'down', 'unknown'] as const;

export interface FilterDraft {
  groups: number[];
  includeSubgroups: boolean;
  /** Tags, custom fields and device facets, as the inventory Filter menu holds them. */
  data: CustomDataFilterValue;
  tagMatch: TagMatch;
  /** Driver keys, comma or newline separated. */
  platforms: string;
  statuses: string[];
  searchMode: SearchMode;
  searchValue: string;
  /** Networks, comma or newline separated. */
  prefixes: string;
}

export const EMPTY_DRAFT: FilterDraft = {
  groups: [],
  includeSubgroups: true,
  data: EMPTY_CUSTOM_DATA_FILTER,
  tagMatch: 'all',
  platforms: '',
  statuses: [],
  searchMode: 'contains',
  searchValue: '',
  prefixes: '',
};

/** Items of a comma / whitespace separated list, trimmed, without repeats. */
export function splitList(text: string): string[] {
  return [...new Set(text.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean))];
}

function deviceToWire(device: DeviceFilterValue | undefined): Partial<Record<DeviceKey, (number | null)[]>> {
  const out: Partial<Record<DeviceKey, (number | null)[]>> = {};
  for (const { key } of DEVICE_FACETS) {
    const choices = device?.[key];
    if (choices && choices.length > 0) out[FACET_KEYS[key]] = choices.map((c) => (c === NONE ? null : c));
  }
  return out;
}

/** The definition a draft describes; empty criteria are left out. */
export function draftToFilter(draft: FilterDraft): DynamicGroupFilter {
  const out: DynamicGroupFilter = { ...deviceToWire(draft.data.device) };
  if (draft.groups.length > 0) {
    out.groups = [...draft.groups];
    out.include_subgroups = draft.includeSubgroups;
  }
  const platforms = splitList(draft.platforms.toLowerCase());
  if (platforms.length > 0) out.platforms = platforms;
  if (draft.statuses.length > 0) out.statuses = [...draft.statuses];
  if (draft.data.tagIds.length > 0) {
    out.tag_ids = [...draft.data.tagIds];
    out.tag_match = draft.tagMatch;
  }
  const fields = Object.entries(draft.data.fields).filter(([, v]) => v !== '');
  if (fields.length > 0) out.custom_fields = Object.fromEntries(fields.map(([k, v]) => [k, [v]]));
  if (draft.searchValue.trim()) out.search = { mode: draft.searchMode, value: draft.searchValue.trim() };
  const prefixes = splitList(draft.prefixes);
  if (prefixes.length > 0) out.prefixes = prefixes;
  return out;
}

/** The draft of a stored definition (a custom field keeps its first value). */
export function filterToDraft(filter: DynamicGroupFilter | null | undefined): FilterDraft {
  const f = filter ?? {};
  const device: DeviceFilterValue = {};
  for (const { key } of DEVICE_FACETS) {
    const values = f[FACET_KEYS[key]];
    if (values && values.length > 0) device[key] = values.map((v): FacetChoice => (v === null ? NONE : v));
  }
  const fields: Record<string, string> = {};
  for (const [key, values] of Object.entries(f.custom_fields ?? {})) {
    if (values.length > 0) fields[key] = values[0];
  }
  return {
    groups: [...(f.groups ?? [])],
    includeSubgroups: f.include_subgroups ?? true,
    data: { tagIds: [...(f.tag_ids ?? [])], fields, device },
    tagMatch: f.tag_match ?? 'any',
    platforms: (f.platforms ?? []).join(', '),
    statuses: [...(f.statuses ?? [])],
    searchMode: f.search?.mode ?? 'contains',
    searchValue: f.search?.value ?? '',
    prefixes: (f.prefixes ?? []).join(', '),
  };
}

/**
 * The draft of the Inventory page's current filter: the Filter menu's tags
 * (all must match, as there), fields and device facets, and the search box
 * as a hostname / IP "contains" match.
 */
export function inventoryFilterToDraft(data: CustomDataFilterValue, query: string): FilterDraft {
  return { ...EMPTY_DRAFT, data, tagMatch: 'all', searchValue: query.trim() };
}

/** How many criteria a definition sets (the builder's "needs a criterion" check). */
export function criteriaCount(filter: DynamicGroupFilter): number {
  return Object.entries(filter).filter(
    ([key, value]) => key !== 'include_subgroups' && key !== 'tag_match' && value !== undefined,
  ).length;
}

/** A stable text form of a definition, for change detection and query keys. */
export function filterKey(filter: DynamicGroupFilter): string {
  const sorted = Object.keys(filter)
    .sort()
    .map((k) => [k, filter[k as keyof DynamicGroupFilter]]);
  return JSON.stringify(sorted);
}

/** A one-line description of a definition, e.g. "2 groups · platform cisco_ios · tags (any of 2)". */
export function describeFilter(filter: DynamicGroupFilter): string {
  const parts: string[] = [];
  const plural = (n: number, one: string) => `${n} ${one}${n === 1 ? '' : 's'}`;
  if (filter.groups?.length) {
    parts.push(plural(filter.groups.length, 'group') + (filter.include_subgroups === false ? '' : ' (with sub-groups)'));
  }
  for (const { key, label } of DEVICE_FACETS) {
    const n = filter[FACET_KEYS[key]]?.length ?? 0;
    if (n) parts.push(`${label.toLowerCase()} (${n})`);
  }
  if (filter.platforms?.length) parts.push(`platform ${filter.platforms.join('/')}`);
  if (filter.statuses?.length) parts.push(`status ${filter.statuses.join('/')}`);
  if (filter.tag_ids?.length) parts.push(`tags (${filter.tag_match === 'all' ? 'all' : 'any'} of ${filter.tag_ids.length})`);
  for (const [key, values] of Object.entries(filter.custom_fields ?? {})) {
    parts.push(values.includes(HAS_VALUE) ? `${key} set` : `${key} = ${values.join('/')}`);
  }
  if (filter.search) parts.push(filter.search.mode === 'regex' ? `name ~ /${filter.search.value}/` : `name contains "${filter.search.value}"`);
  if (filter.prefixes?.length) parts.push(`in ${filter.prefixes.join(', ')}`);
  return parts.join(' · ') || 'No criteria';
}
