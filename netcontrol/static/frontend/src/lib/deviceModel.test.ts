import { describe, expect, it } from 'vitest';

import type { InventoryHost } from '@/api/inventory';

import { type CustomDataFilterValue, EMPTY_CUSTOM_DATA_FILTER, filterCount, isEmptyFilter } from './customData';
import {
  bulkEditSet,
  changedHostDeviceFields,
  deviceTypeOptionGroups,
  EMPTY_BULK_EDIT,
  hostModelText,
  initialHostDeviceValues,
  KEEP,
  matchesDeviceFilter,
  NONE,
  selectToBulkChoice,
  selectToId,
  toggleFacetChoice,
} from './deviceModel';

const host = (partial: Partial<InventoryHost> = {}): InventoryHost => ({
  id: 1,
  hostname: 'sw-lab-01',
  ip_address: '192.0.2.10',
  ...partial,
});

const linked = host({
  device_type_id: 7,
  role_id: 2,
  lifecycle_status_id: 1,
  site_id: 3,
  location_detail: 'Row 4, rack 12',
  hardware: { id: 7, model: 'EX-4800', manufacturer_id: 5, manufacturer: 'Example Networks' },
});

describe('matchesDeviceFilter', () => {
  it('matches everything without choices', () => {
    expect(matchesDeviceFilter(host(), undefined)).toBe(true);
    expect(matchesDeviceFilter(linked, {})).toBe(true);
    expect(matchesDeviceFilter(linked, { role: [] })).toBe(true);
  });

  it('treats the choices of one facet as alternatives', () => {
    expect(matchesDeviceFilter(linked, { role: [2] })).toBe(true);
    expect(matchesDeviceFilter(linked, { role: [9, 2] })).toBe(true);
    expect(matchesDeviceFilter(linked, { role: [9] })).toBe(false);
  });

  it('needs every facet with a choice to match', () => {
    expect(matchesDeviceFilter(linked, { role: [2], site: [3], manufacturer: [5] })).toBe(true);
    expect(matchesDeviceFilter(linked, { role: [2], site: [4] })).toBe(false);
    expect(matchesDeviceFilter(linked, { device_type: [7], lifecycle_status: [2] })).toBe(false);
  });

  it('matches None to a missing value only', () => {
    expect(matchesDeviceFilter(host(), { role: [NONE] })).toBe(true);
    expect(matchesDeviceFilter(host({ role_id: null }), { role: [NONE] })).toBe(true);
    expect(matchesDeviceFilter(linked, { role: [NONE] })).toBe(false);
    expect(matchesDeviceFilter(linked, { role: [NONE, 2] })).toBe(true);
    // The manufacturer comes from the linked device type.
    expect(matchesDeviceFilter(host({ model: 'raw text' }), { manufacturer: [NONE] })).toBe(true);
    expect(matchesDeviceFilter(linked, { manufacturer: [NONE] })).toBe(false);
  });
});

describe('toggleFacetChoice and the filter count', () => {
  it('adds and removes a choice, dropping an emptied facet', () => {
    const one = toggleFacetChoice(undefined, 'role', 2);
    expect(one).toEqual({ role: [2] });
    const two = toggleFacetChoice(one, 'role', NONE);
    expect(two).toEqual({ role: [2, NONE] });
    expect(toggleFacetChoice(toggleFacetChoice(two, 'role', 2), 'role', NONE)).toEqual({});
  });

  it('counts device choices with the tag and field criteria', () => {
    expect(isEmptyFilter({ ...EMPTY_CUSTOM_DATA_FILTER, device: {} })).toBe(true);
    const filter: CustomDataFilterValue = { tagIds: [1], fields: { env: 'lab' }, device: { role: [2, NONE], site: [3] } };
    expect(filterCount(filter)).toBe(5);
    expect(isEmptyFilter(filter)).toBe(false);
  });
});

describe('deviceTypeOptionGroups', () => {
  it('groups models by manufacturer, both sorted by name', () => {
    const groups = deviceTypeOptionGroups([
      { id: 3, manufacturer: 'Example Networks', model: 'EX-4800' },
      { id: 1, manufacturer: 'Acme', model: 'Z-100' },
      { id: 2, manufacturer: 'Example Networks', model: 'EX-2300' },
      { id: 4, manufacturer: 'Acme', model: 'A-10' },
    ]);
    expect(groups).toEqual([
      {
        label: 'Acme',
        options: [
          { value: 4, label: 'A-10' },
          { value: 1, label: 'Z-100' },
        ],
      },
      {
        label: 'Example Networks',
        options: [
          { value: 2, label: 'EX-2300' },
          { value: 3, label: 'EX-4800' },
        ],
      },
    ]);
  });

  it('returns no groups without device types', () => {
    expect(deviceTypeOptionGroups([])).toEqual([]);
  });
});

describe('changedHostDeviceFields', () => {
  it('sends nothing when nothing changed', () => {
    const initial = initialHostDeviceValues(linked, 1);
    expect(changedHostDeviceFields(initial, { ...initial })).toEqual({});
  });

  it('sends only the changed keys, null for None', () => {
    const initial = initialHostDeviceValues(linked, 1);
    expect(changedHostDeviceFields(initial, { ...initial, role_id: null, site_id: 4 })).toEqual({ role_id: null, site_id: 4 });
    expect(changedHostDeviceFields(initial, { ...initial, location_detail: '  Room 2 ' })).toEqual({
      location_detail: 'Room 2',
    });
    expect(changedHostDeviceFields(initial, { ...initial, location_detail: 'Row 4, rack 12 ' })).toEqual({});
  });

  it('starts a new host on the default status and does not send it unchanged', () => {
    const initial = initialHostDeviceValues(null, 1);
    expect(initial).toEqual({ device_type_id: null, role_id: null, lifecycle_status_id: 1, site_id: null, location_detail: '' });
    expect(changedHostDeviceFields(initial, initial)).toEqual({});
    expect(changedHostDeviceFields(initial, { ...initial, device_type_id: 7, lifecycle_status_id: 2 })).toEqual({
      device_type_id: 7,
      lifecycle_status_id: 2,
    });
  });

  it('reads a row from a server without the device model as all empty', () => {
    expect(initialHostDeviceValues(host(), 1)).toEqual({
      device_type_id: null,
      role_id: null,
      lifecycle_status_id: null,
      site_id: null,
      location_detail: '',
    });
  });
});

describe('bulkEditSet', () => {
  it('is empty when every value is left unchanged', () => {
    expect(bulkEditSet(EMPTY_BULK_EDIT)).toEqual({});
  });

  it('holds only the changed values, null for None', () => {
    expect(
      bulkEditSet({ ...EMPTY_BULK_EDIT, role_id: 2, site_id: null, location_detail: ' Rack 9 ' }),
    ).toEqual({ role_id: 2, site_id: null, location_detail: 'Rack 9' });
    expect(bulkEditSet({ ...EMPTY_BULK_EDIT, location_detail: '' })).toEqual({ location_detail: '' });
  });

  it('reads the select values', () => {
    expect(selectToBulkChoice(KEEP)).toBe(KEEP);
    expect(selectToBulkChoice('')).toBeNull();
    expect(selectToBulkChoice('12')).toBe(12);
    expect(selectToId('')).toBeNull();
    expect(selectToId('5')).toBe(5);
  });
});

describe('hostModelText', () => {
  it('prefers the linked device type, then the raw model', () => {
    expect(hostModelText(linked)).toBe('Example Networks EX-4800');
    expect(hostModelText(host({ model: 'EX-2300-C' }))).toBe('EX-2300-C');
    expect(hostModelText(host())).toBe('-');
  });
});
