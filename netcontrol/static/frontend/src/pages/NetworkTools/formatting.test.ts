import { describe, expect, it } from 'vitest';

import { flowInterfaceLabel, formatBytes } from './formatting';

describe('flowInterfaceLabel', () => {
  it('names the interface with its device when they differ', () => {
    expect(flowInterfaceLabel({ if_index: 2, if_name: 'LAN', if_device: 'igb1' })).toBe('LAN (igb1)');
  });

  it('shows one name when name and device are the same', () => {
    expect(flowInterfaceLabel({ if_index: 3, if_name: 'Gi0/1', if_device: 'Gi0/1' })).toBe('Gi0/1');
  });

  it('falls back to the index when the host has no names', () => {
    expect(flowInterfaceLabel({ if_index: 7, if_name: null, if_device: null })).toBe('ifIndex 7');
    expect(flowInterfaceLabel({ if_index: 0 })).toBe('None (index 0)');
  });
});

describe('formatBytes', () => {
  it('scales to the largest unit', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(2048)).toBe('2.0 KB');
  });
});
