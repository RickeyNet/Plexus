import { describe, expect, it } from 'vitest';

import { actionLabel, actionTone, diffRows, formatChangeValue, objectTypeLabel } from './objectChanges';

describe('diffRows', () => {
  it('lists the changed fields of an update, sorted', () => {
    const rows = diffRows({
      action: 'update',
      changes: {
        ip_address: { before: '192.0.2.10', after: '192.0.2.11' },
        hostname: { before: 'edge-r1', after: 'edge-r2' },
      },
      before: { id: 5, hostname: 'edge-r1', ip_address: '192.0.2.10' },
      after: { id: 5, hostname: 'edge-r2', ip_address: '192.0.2.11' },
    });
    expect(rows).toEqual([
      { field: 'hostname', before: 'edge-r1', after: 'edge-r2', kind: 'changed' },
      { field: 'ip_address', before: '192.0.2.10', after: '192.0.2.11', kind: 'changed' },
    ]);
  });

  it('shows every set field of a created object, without the id', () => {
    const rows = diffRows({
      action: 'create',
      changes: {},
      before: null,
      after: { id: 7, name: 'blue', rd: '', description: null, origin: 'manual' },
    });
    expect(rows).toEqual([
      { field: 'name', before: null, after: 'blue', kind: 'added' },
      { field: 'origin', before: null, after: 'manual', kind: 'added' },
    ]);
  });

  it('shows the last state of a deleted object as before values', () => {
    const rows = diffRows({ action: 'delete', changes: {}, before: { id: 3, vid: 120 }, after: null });
    expect(rows).toEqual([{ field: 'vid', before: 120, after: null, kind: 'removed' }]);
  });

  it('is empty when nothing was recorded', () => {
    expect(diffRows({ action: 'update', changes: {}, before: null, after: null })).toEqual([]);
    expect(diffRows({ action: 'create', changes: {}, before: null, after: null })).toEqual([]);
  });
});

describe('formatChangeValue', () => {
  it('renders empties as a dash and structures as JSON', () => {
    expect(formatChangeValue(null)).toBe('-');
    expect(formatChangeValue(undefined)).toBe('-');
    expect(formatChangeValue('')).toBe('-');
    expect(formatChangeValue('core')).toBe('core');
    expect(formatChangeValue(0)).toBe('0');
    expect(formatChangeValue(false)).toBe('false');
    expect(formatChangeValue([1, 2])).toBe('[1,2]');
    expect(formatChangeValue({ a: 'b' })).toBe('{"a":"b"}');
  });
});

describe('labels and tones', () => {
  it('names actions and types', () => {
    expect(actionLabel('create')).toBe('Create');
    expect(actionLabel('')).toBe('-');
    expect(actionTone('create')).toBe('success');
    expect(actionTone('delete')).toBe('danger');
    expect(actionTone('other')).toBe('neutral');
    expect(objectTypeLabel('ip_address')).toBe('IP address');
    expect(objectTypeLabel('widget')).toBe('widget');
  });
});
