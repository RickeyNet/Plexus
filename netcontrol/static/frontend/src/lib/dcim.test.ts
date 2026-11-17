import { describe, expect, it } from 'vitest';

import {
  blockUnitsLabel,
  endpointLabel,
  fieldValue,
  formatUnits,
  formatWatts,
  parseUnits,
  traceFromParams,
  traceLink,
  traceStatusText,
} from './dcim';

describe('parseUnits', () => {
  it('reads units and ranges, sorted without repeats', () => {
    expect(parseUnits('7, 1-3, 2')).toEqual([1, 2, 3, 7]);
    expect(parseUnits(' 5 ')).toEqual([5]);
  });

  it('refuses text that is not units', () => {
    expect(parseUnits('')).toBeNull();
    expect(parseUnits('a')).toBeNull();
    expect(parseUnits('3-1')).toBeNull();
    expect(parseUnits('0')).toBeNull();
  });
});

describe('formatUnits', () => {
  it('writes runs', () => {
    expect(formatUnits([7, 1, 2, 3])).toBe('1-3, 7');
    expect(formatUnits([])).toBe('');
  });
});

describe('labels', () => {
  it('names an endpoint', () => {
    expect(endpointLabel({ type: 'interface', host_name: 'sw1', name: 'Gi1' })).toBe('sw1 / Gi1');
    expect(endpointLabel({ type: 'front_port', id: 4, label: 'pp / F1' })).toBe('pp / F1');
    expect(endpointLabel({ type: 'power_feed', id: 9 })).toBe('#9');
    expect(endpointLabel(null)).toBe('-');
  });

  it('formats watts, units and trace states', () => {
    expect(formatWatts(850)).toBe('850 W');
    expect(formatWatts(3680)).toBe('3.7 kW');
    expect(formatWatts(null)).toBe('-');
    expect(blockUnitsLabel([4, 3])).toBe('U3-U4');
    expect(blockUnitsLabel([7])).toBe('U7');
    expect(traceStatusText('loop')).toMatch(/loops/);
  });
});

describe('form values and trace links', () => {
  it('converts field input', () => {
    expect(fieldValue({ key: 'u', label: 'Units', kind: 'units' }, '1-2')).toEqual({ value: [1, 2] });
    expect(fieldValue({ key: 'h', label: 'Height', kind: 'number', min: 1 }, '0').error).toMatch(/at least 1/);
    expect(fieldValue({ key: 'r', label: 'Role', kind: 'ref' }, '')).toEqual({
      value: null,
    });
    expect(fieldValue({ key: 's', label: 'Site', kind: 'ref', required: true }, '').error).toMatch(/required/);
    expect(fieldValue({ key: 'n', label: 'Name', kind: 'text' }, '  R01 ')).toEqual({ value: 'R01' });
    expect(fieldValue({ key: 'd', label: 'Desc', kind: 'checkbox' }, true)).toEqual({ value: true });
  });

  it('round-trips a trace through the URL', () => {
    const link = traceLink({ type: 'interface', host_id: 4, name: 'Gi1/0/1' });
    expect(link.startsWith('/dcim/cables?')).toBe(true);
    expect(traceFromParams(new URLSearchParams(link.split('?')[1]))).toEqual({
      type: 'interface',
      host_id: 4,
      name: 'Gi1/0/1',
    });
    expect(traceFromParams(new URLSearchParams('trace_type=front_port&trace_id=7'))).toEqual({ type: 'front_port', id: 7 });
    expect(traceFromParams(new URLSearchParams(''))).toBeNull();
  });
});
