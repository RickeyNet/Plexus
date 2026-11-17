import { describe, expect, it } from 'vitest';

import {
  cloudResourceLabel,
  countToText,
  formatMemory,
  parseAddressList,
  parseOptionalCount,
  vmStatusLabel,
  vmStatusTone,
} from './virtualization';

describe('virtualization helpers', () => {
  it('maps statuses to tones and labels', () => {
    expect(vmStatusTone('active')).toBe('success');
    expect(vmStatusTone('failed')).toBe('danger');
    expect(vmStatusTone('unknown')).toBe('neutral');
    expect(vmStatusLabel('decommissioning')).toBe('Decommissioning');
    expect(vmStatusLabel('')).toBe('-');
  });

  it('parses optional counts', () => {
    expect(parseOptionalCount('', 10)).toBeNull();
    expect(parseOptionalCount(' 4 ', 10)).toBe(4);
    expect(parseOptionalCount('11', 10)).toBeUndefined();
    expect(parseOptionalCount('-1', 10)).toBeUndefined();
    expect(parseOptionalCount('1.5', 10)).toBeUndefined();
    expect(countToText(null)).toBe('');
    expect(countToText(0)).toBe('0');
  });

  it('splits address lists', () => {
    expect(parseAddressList('192.0.2.1/24\n2001:db8::1/64, 192.0.2.1/24  198.51.100.2/32')).toEqual([
      '192.0.2.1/24',
      '2001:db8::1/64',
      '198.51.100.2/32',
    ]);
    expect(parseAddressList('  ')).toEqual([]);
  });

  it('formats memory', () => {
    expect(formatMemory(null)).toBe('-');
    expect(formatMemory(512)).toBe('512 MB');
    expect(formatMemory(8192)).toBe('8 GB');
    expect(formatMemory(1536)).toBe('1.5 GB');
  });

  it('names the cloud resource', () => {
    const base = { cloud_resource_name: 'web-1', cloud_account_name: 'demo' };
    expect(cloudResourceLabel({ ...base, cloud_provider: 'aws', cloud_resource_type: 'instance' })).toBe(
      'AWS instance web-1 (demo)',
    );
    expect(cloudResourceLabel({ ...base, cloud_provider: 'azure', cloud_resource_type: 'vm' })).toBe('Azure VM web-1 (demo)');
    expect(cloudResourceLabel({ ...base, cloud_provider: null, cloud_resource_type: null })).toBe('');
  });
});
