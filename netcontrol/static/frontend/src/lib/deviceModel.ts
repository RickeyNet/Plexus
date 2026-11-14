/**
 * Pure helpers for the device model on hosts: the browser-side facet filter,
 * the select option builders, the host dialog's changed-keys payload and the
 * bulk edit `set`.
 */
import type { BulkEditSet, DeviceType } from '@/api/deviceModel';
import type { HostDeviceFields, InventoryHost } from '@/api/inventory';

/** The longest rack / room text a host takes. */
export const LOCATION_DETAIL_MAX = 200;

// ── Facet filter ───────────────────────────────────────────────────────────

/** The filter choice that matches a host with no value. */
export const NONE = 'none';
export type FacetChoice = number | typeof NONE;

export type DeviceFacet = 'manufacturer' | 'device_type' | 'role' | 'lifecycle_status' | 'site';

export const DEVICE_FACETS: readonly { key: DeviceFacet; label: string }[] = [
  { key: 'manufacturer', label: 'Manufacturer' },
  { key: 'device_type', label: 'Device type' },
  { key: 'role', label: 'Role' },
  { key: 'lifecycle_status', label: 'Lifecycle status' },
  { key: 'site', label: 'Site' },
];

/** The chosen values per facet; a facet absent or empty does not filter. */
export type DeviceFilterValue = Partial<Record<DeviceFacet, FacetChoice[]>>;

export type DeviceFilterRow = Pick<
  InventoryHost,
  'device_type_id' | 'role_id' | 'lifecycle_status_id' | 'site_id' | 'hardware'
>;

/** A host's value for a facet, null when it has none. */
export function hostFacetValue(host: DeviceFilterRow, facet: DeviceFacet): number | null {
  switch (facet) {
    case 'manufacturer':
      return host.hardware?.manufacturer_id ?? null;
    case 'device_type':
      return host.device_type_id ?? null;
    case 'role':
      return host.role_id ?? null;
    case 'lifecycle_status':
      return host.lifecycle_status_id ?? null;
    case 'site':
      return host.site_id ?? null;
  }
}

/** How many choices the filter holds (for the count badge). */
export function deviceFilterCount(filter: DeviceFilterValue | undefined): number {
  return DEVICE_FACETS.reduce((sum, { key }) => sum + (filter?.[key]?.length ?? 0), 0);
}

export function isEmptyDeviceFilter(filter: DeviceFilterValue | undefined): boolean {
  return deviceFilterCount(filter) === 0;
}

/**
 * Whether a host matches: the choices of one facet are alternatives, every
 * facet with a choice must match, and `NONE` matches a host with no value.
 */
export function matchesDeviceFilter(host: DeviceFilterRow, filter: DeviceFilterValue | undefined): boolean {
  return DEVICE_FACETS.every(({ key }) => {
    const choices = filter?.[key];
    if (!choices || choices.length === 0) return true;
    const value = hostFacetValue(host, key);
    return choices.includes(value === null ? NONE : value);
  });
}

/** `filter` with `choice` added to or taken out of `facet`. */
export function toggleFacetChoice(filter: DeviceFilterValue | undefined, facet: DeviceFacet, choice: FacetChoice): DeviceFilterValue {
  const current = filter?.[facet] ?? [];
  const next = current.includes(choice) ? current.filter((c) => c !== choice) : [...current, choice];
  const out: DeviceFilterValue = { ...filter };
  if (next.length) out[facet] = next;
  else delete out[facet];
  return out;
}

// ── Select options ─────────────────────────────────────────────────────────

export interface SelectOption {
  value: number;
  label: string;
}

export interface SelectOptionGroup {
  label: string;
  options: SelectOption[];
}

/** Device types as `<optgroup>`s per manufacturer, manufacturers and models by name. */
export function deviceTypeOptionGroups(types: Pick<DeviceType, 'id' | 'manufacturer' | 'model'>[]): SelectOptionGroup[] {
  const groups = new Map<string, SelectOption[]>();
  for (const t of types) {
    const label = t.manufacturer || 'Unknown';
    const list = groups.get(label) ?? [];
    list.push({ value: t.id, label: t.model });
    groups.set(label, list);
  }
  return [...groups.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([label, options]) => ({ label, options: options.sort((a, b) => a.label.localeCompare(b.label)) }));
}

/** A `<select>` value for an id ('' for none). */
export function idToSelect(id: number | null | undefined): string {
  return id === null || id === undefined ? '' : String(id);
}

/** The id a `<select>` value names (null for ''). */
export function selectToId(value: string): number | null {
  if (value === '') return null;
  const n = Number(value);
  return Number.isInteger(n) ? n : null;
}

// ── Host dialog ────────────────────────────────────────────────────────────

export interface HostDeviceValues {
  device_type_id: number | null;
  role_id: number | null;
  lifecycle_status_id: number | null;
  site_id: number | null;
  location_detail: string;
}

/** The id values a host stores, in form order. */
export const DEVICE_ID_KEYS = ['device_type_id', 'role_id', 'lifecycle_status_id', 'site_id'] as const;
export type DeviceIdKey = (typeof DEVICE_ID_KEYS)[number];

/**
 * The dialog's starting values: the host's own, or for a new host nothing but
 * the default lifecycle status.
 */
export function initialHostDeviceValues(host: InventoryHost | null, defaultStatusId: number | null): HostDeviceValues {
  if (!host) {
    return { device_type_id: null, role_id: null, lifecycle_status_id: defaultStatusId, site_id: null, location_detail: '' };
  }
  return {
    device_type_id: host.device_type_id ?? null,
    role_id: host.role_id ?? null,
    lifecycle_status_id: host.lifecycle_status_id ?? null,
    site_id: host.site_id ?? null,
    location_detail: host.location_detail ?? '',
  };
}

/**
 * The keys the user changed, for the host create or update body. Untouched
 * keys stay out so a save does not lock a value discovery filled in (sending
 * `device_type_id` or `role_id` locks it). Rack / room text is trimmed.
 */
export function changedHostDeviceFields(initial: HostDeviceValues, current: HostDeviceValues): HostDeviceFields {
  const out: HostDeviceFields = {};
  for (const key of DEVICE_ID_KEYS) {
    if (current[key] !== initial[key]) out[key] = current[key];
  }
  const detail = current.location_detail.trim();
  if (detail !== initial.location_detail.trim()) out.location_detail = detail;
  return out;
}

// ── Bulk edit ──────────────────────────────────────────────────────────────

/** The bulk edit choice that leaves a value as each host has it. */
export const KEEP = 'keep';
export type BulkIdChoice = typeof KEEP | number | null;

export interface BulkEditForm {
  device_type_id: BulkIdChoice;
  role_id: BulkIdChoice;
  lifecycle_status_id: BulkIdChoice;
  site_id: BulkIdChoice;
  /** The new text ('' clears it); null leaves it unchanged. */
  location_detail: string | null;
}

export const EMPTY_BULK_EDIT: BulkEditForm = {
  device_type_id: KEEP,
  role_id: KEEP,
  lifecycle_status_id: KEEP,
  site_id: KEEP,
  location_detail: null,
};

/** A bulk edit `<select>` value: 'keep', '' for none, or the id. */
export function bulkChoiceToSelect(choice: BulkIdChoice): string {
  return choice === KEEP ? KEEP : idToSelect(choice);
}

export function selectToBulkChoice(value: string): BulkIdChoice {
  return value === KEEP ? KEEP : selectToId(value);
}

/** The request's `set`: only the values the user changed from "leave unchanged". */
export function bulkEditSet(form: BulkEditForm): BulkEditSet {
  const out: BulkEditSet = {};
  for (const key of DEVICE_ID_KEYS) {
    const choice = form[key];
    if (choice !== KEEP) out[key] = choice;
  }
  if (form.location_detail !== null) out.location_detail = form.location_detail.trim();
  return out;
}

// ── Display ────────────────────────────────────────────────────────────────

/** "Cisco C9300-48P" when linked to a device type, else the discovered model text, else '-'. */
export function hostModelText(host: Pick<InventoryHost, 'hardware' | 'model'>): string {
  if (host.hardware) return `${host.hardware.manufacturer} ${host.hardware.model}`.trim();
  return host.model || '-';
}
