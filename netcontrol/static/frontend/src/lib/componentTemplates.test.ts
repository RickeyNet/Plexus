import { describe, expect, it } from 'vitest';

import type { InstantiateResult } from '@/api/dcim';

import { componentTypeLabel, instantiateSummary } from './componentTemplates';

const base: InstantiateResult = {
  host_id: 4,
  device_type_id: 2,
  created: {},
  created_count: 0,
  skipped: 0,
  errors: [],
  interfaces: { expected: [], missing: [] },
};

describe('component templates', () => {
  it('labels component types', () => {
    expect(componentTypeLabel('module_bay')).toBe('Module bay');
    expect(componentTypeLabel('fan')).toBe('fan');
  });

  it('says when the device has no device type', () => {
    expect(instantiateSummary({ ...base, device_type_id: null })).toContain('no device type');
  });

  it('lists what was created, what existed and the unreported interfaces', () => {
    const text = instantiateSummary({
      ...base,
      created: { console_port: ['con0'], front_port: ['F1', 'F2'] },
      created_count: 3,
      skipped: 1,
      errors: [{ kind: 'front_port', name: 'F3', message: 'Its rear port does not exist.' }],
      interfaces: { expected: ['eth0', 'eth1'], missing: ['eth1'] },
    });
    expect(text).toContain('Created 1 console port (con0); 2 front ports (F1, F2).');
    expect(text).toContain('1 component existed already');
    expect(text).toContain('F3: Its rear port does not exist.');
    expect(text).toContain('has not reported yet: eth1.');
  });

  it('says when nothing was missing', () => {
    const text = instantiateSummary({ ...base, skipped: 2, interfaces: { expected: ['eth0'], missing: [] } });
    expect(text).toContain('Nothing new to create');
    expect(text).toContain('2 components existed already');
    expect(text).toContain('reports every interface');
  });
});
