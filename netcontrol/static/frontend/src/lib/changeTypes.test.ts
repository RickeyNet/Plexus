import { describe, expect, it } from 'vitest';

import { changeTypeLabel, changeTypeOptions } from './changeTypes';

describe('changeTypeLabel', () => {
  it('names known change types', () => {
    expect(changeTypeLabel('nat')).toBe('NAT');
    expect(changeTypeLabel('policy')).toBe('Policy / ACL');
  });

  it('passes unknown values through and reads missing as "-"', () => {
    expect(changeTypeLabel('custom')).toBe('custom');
    expect(changeTypeLabel(null)).toBe('-');
  });
});

describe('changeTypeOptions', () => {
  it('keeps the order given', () => {
    expect(changeTypeOptions(['route', 'template'])).toEqual([
      { value: 'route', label: 'Route' },
      { value: 'template', label: 'Template' },
    ]);
  });
});
