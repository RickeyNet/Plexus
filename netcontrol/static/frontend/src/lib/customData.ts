/**
 * Pure helpers for custom fields and tags: the tag color palette, the
 * browser-side filter predicate shared by the Inventory and IPAM lists, form
 * initial values and the tag picker's option list.
 */
import type {
  CustomField,
  CustomFieldInput,
  CustomValue,
  FieldType,
  ObjectDataPut,
  ObjectType,
  TagRef,
} from '@/api/customData';

import { deviceFilterCount, type DeviceFilterValue } from './deviceModel';

/** Tag color palette slots; the stylesheet maps each to a theme-aware pair. */
export const TAG_COLORS = ['gray', 'red', 'orange', 'yellow', 'green', 'teal', 'blue', 'purple'] as const;
export type TagColor = (typeof TAG_COLORS)[number];

export const TAG_NAME_MAX = 50;
export const FIELD_KEY_RE = /^[a-z][a-z0-9_]{0,49}$/;

export const OBJECT_TYPES: readonly ObjectType[] = ['host', 'group', 'prefix'];
export const FIELD_TYPES: readonly FieldType[] = ['text', 'number', 'boolean', 'date', 'url', 'select'];

export const OBJECT_TYPE_LABELS: Record<ObjectType, { one: string; many: string; title: string }> = {
  host: { one: 'host', many: 'hosts', title: 'Hosts' },
  group: { one: 'group', many: 'groups', title: 'Groups' },
  prefix: { one: 'IPAM prefix', many: 'IPAM prefixes', title: 'IPAM prefixes' },
};

export const FIELD_TYPE_LABELS: Record<FieldType, string> = {
  text: 'Text',
  number: 'Number',
  boolean: 'Yes / No',
  date: 'Date',
  url: 'URL',
  select: 'Choice list',
};

/** The class that colors a tag chip; unknown colors fall back to gray. */
export function tagColorClass(color: string | null | undefined): string {
  const slot = (TAG_COLORS as readonly string[]).includes(color ?? '') ? color : 'gray';
  return `tag-chip-${slot}`;
}

/** "Gray", "Teal"... */
export function tagColorLabel(color: string): string {
  return color.charAt(0).toUpperCase() + color.slice(1);
}

/** "1 host", "4 groups", "2 IPAM prefixes". */
export function countObjects(count: number, type?: ObjectType): string {
  if (!type) return `${count} object${count === 1 ? '' : 's'}`;
  const label = OBJECT_TYPE_LABELS[type];
  return `${count} ${count === 1 ? label.one : label.many}`;
}

// ── Filter ─────────────────────────────────────────────────────────────────

/**
 * A filter over inline tags and values. A field value of `'*'` means "has any
 * value". Host lists add `device`, the device model facets (applied by
 * `matchesDeviceFilter`, not by `matchesCustomData`).
 */
export interface CustomDataFilterValue {
  tagIds: number[];
  fields: Record<string, string>;
  device?: DeviceFilterValue;
}

export const HAS_VALUE = '*';

export const EMPTY_CUSTOM_DATA_FILTER: CustomDataFilterValue = { tagIds: [], fields: {} };

export interface CustomDataRow {
  tags?: TagRef[];
  custom_fields?: Record<string, CustomValue>;
}

export function isEmptyFilter(filter: CustomDataFilterValue): boolean {
  return filterCount(filter) === 0;
}

/** How many criteria the filter holds (for the count badge). */
export function filterCount(filter: CustomDataFilterValue): number {
  return filter.tagIds.length + Object.keys(filter.fields).length + deviceFilterCount(filter.device);
}

/** A stored value as text: `true`, `2`, `prod`. Missing values are ''. */
export function valueText(value: CustomValue | null | undefined): string {
  return value === null || value === undefined ? '' : String(value);
}

/** Whether a row carries every selected tag and every field value (compared as text). */
export function matchesCustomData(row: CustomDataRow, filter: CustomDataFilterValue): boolean {
  const tagIds = new Set((row.tags ?? []).map((t) => t.id));
  if (!filter.tagIds.every((id) => tagIds.has(id))) return false;
  const values = row.custom_fields ?? {};
  return Object.entries(filter.fields).every(([key, wanted]) => {
    const actual = valueText(values[key]);
    return wanted === HAS_VALUE ? actual !== '' : actual === wanted;
  });
}

// ── Form values ────────────────────────────────────────────────────────────

export type FormValues = Record<string, CustomValue | ''>;

/** The fields that apply to an object type, in display order. */
export function applicableFields(fields: CustomField[], objectType: ObjectType): CustomField[] {
  return fields
    .filter((f) => f.object_types.includes(objectType))
    .sort((a, b) => a.sort_order - b.sort_order || a.id - b.id);
}

/** A field's default as a form value ('' when it has none). */
function defaultValue(field: CustomField): CustomValue | '' {
  const raw = field.default_value ?? '';
  if (raw === '') return '';
  if (field.field_type === 'boolean') return raw === 'true';
  return raw;
}

/** Each field's form value: the stored value, else the default, else ''. */
export function initialFieldValues(fields: CustomField[], stored: Record<string, CustomValue>): FormValues {
  const out: FormValues = {};
  for (const field of fields) {
    const value = stored[field.key];
    out[field.key] = value !== undefined && value !== null && value !== '' ? value : defaultValue(field);
  }
  return out;
}

/** The `fields` of a save: every given field, '' sent as null (cleared). Text is trimmed. */
export function toPutFields(fields: CustomField[], values: FormValues): ObjectDataPut['fields'] {
  const out: ObjectDataPut['fields'] = {};
  for (const field of fields) {
    const value = values[field.key];
    const trimmed = typeof value === 'string' ? value.trim() : value;
    out[field.key] = trimmed === '' || trimmed === undefined ? null : trimmed;
  }
  return out;
}

/** "Owner is required." for each required field with no value. */
export function missingRequired(fields: CustomField[], values: FormValues): Record<string, string> {
  const errors: Record<string, string> = {};
  for (const field of fields) {
    if (!field.required) continue;
    const value = values[field.key];
    if (value === '' || value === undefined || (typeof value === 'string' && !value.trim())) {
      errors[field.key] = `${field.label} is required.`;
    }
  }
  return errors;
}

/** A stored value for display: booleans as Yes / No. */
export function formatCustomValue(field: Pick<CustomField, 'field_type'>, value: CustomValue | null | undefined): string {
  if (value === null || value === undefined || value === '') return '';
  if (field.field_type === 'boolean') return value === true || value === 'true' ? 'Yes' : 'No';
  return String(value);
}

// ── Tag picker ─────────────────────────────────────────────────────────────

/** `value` with `id` added, or removed when it is already there. */
export function toggleTag(value: number[], id: number): number[] {
  return value.includes(id) ? value.filter((v) => v !== id) : [...value, id];
}

export interface TagPickerOptions {
  /** Unselected tags whose name contains the typed text. */
  matches: TagRef[];
  /** The name to offer "Create tag" for, or null. */
  createName: string | null;
}

/**
 * What the tag picker lists for the typed text: the unselected tags whose name
 * contains it, and a tag to create when no tag has that exact name (ignoring
 * case) and the user may create one.
 */
export function tagPickerOptions(
  tags: TagRef[],
  selected: number[],
  query: string,
  canCreate: boolean,
): TagPickerOptions {
  const q = query.trim().toLowerCase();
  const chosen = new Set(selected);
  const matches = tags
    .filter((t) => !chosen.has(t.id) && t.name.toLowerCase().includes(q))
    .sort((a, b) => a.name.localeCompare(b.name));
  const exists = tags.some((t) => t.name.toLowerCase() === q);
  const name = query.trim();
  const createName = canCreate && name && name.length <= TAG_NAME_MAX && !exists ? name : null;
  return { matches, createName };
}

// ── Field definition form ──────────────────────────────────────────────────

/** A key made from a label: "Asset owner" -> "asset_owner". '' when nothing usable is left. */
export function suggestFieldKey(label: string): string {
  const slug = label
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^[^a-z]+/, '')
    .replace(/_+$/, '')
    .slice(0, 50)
    .replace(/_+$/, '');
  return FIELD_KEY_RE.test(slug) ? slug : '';
}

/** The choices typed one per line: trimmed, blanks and repeats dropped. */
export function parseChoices(text: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const line of text.split('\n')) {
    const choice = line.trim();
    if (choice && !seen.has(choice)) {
      seen.add(choice);
      out.push(choice);
    }
  }
  return out;
}

export type FieldFormErrors = Partial<Record<'label' | 'key' | 'object_types' | 'choices' | 'default_value', string>>;

/** Client-side checks of a field definition; the server checks again. */
export function validateFieldForm(input: CustomFieldInput, isCreate: boolean): FieldFormErrors {
  const errors: FieldFormErrors = {};
  if (!input.label.trim()) errors.label = 'Label is required.';
  if (isCreate && !FIELD_KEY_RE.test(input.key)) {
    errors.key = 'Key must start with a lowercase letter and use only a-z, 0-9 and _ (50 characters at most).';
  }
  if (input.object_types.length === 0) errors.object_types = 'Choose at least one object type.';
  if (input.field_type === 'select' && input.choices.length === 0) errors.choices = 'Add at least one choice.';
  if (input.field_type === 'select' && input.default_value && !input.choices.includes(input.default_value)) {
    errors.default_value = 'The default must be one of the choices.';
  }
  return errors;
}
