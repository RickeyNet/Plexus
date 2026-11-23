import { describe, expect, it } from 'vitest';

import { EVENT_TYPES, eventHostLabel, trapName } from './events';

describe('event type filter', () => {
  it('sends the stored event_type values', () => {
    // The receiver stores traps with event_type "trap": "snmp_trap" matched nothing.
    expect(EVENT_TYPES.map((t) => t.value)).toEqual(['syslog', 'trap']);
    expect(EVENT_TYPES.find((t) => t.value === 'trap')?.label).toBe('SNMP Trap');
  });
});

describe('eventHostLabel', () => {
  it('prefers the hostname, then the host id, then the source address', () => {
    expect(eventHostLabel({ hostname: 'core-sw1', host_id: 3, source_ip: '192.0.2.1' })).toBe('core-sw1');
    expect(eventHostLabel({ host_id: 3, source_ip: '192.0.2.1' })).toBe('3');
    expect(eventHostLabel({ source_ip: '203.0.113.9' })).toBe('203.0.113.9');
    expect(eventHostLabel({})).toBe('-');
  });
});

describe('trapName', () => {
  it('reads the trap name of a named trap message', () => {
    expect(trapName('linkDown: ifIndex 12, ifAdminStatus up, ifOperStatus down')).toBe('linkDown');
    expect(trapName('coldStart: Agent started: the device reloaded or powered on')).toBe('coldStart');
  });

  it('is empty for an unknown or undecoded trap', () => {
    expect(trapName('SNMP trap 1.3.6.1.4.1.99999.0.1: 1.3.6.1.4.1.99999.1.0 = x')).toBe('');
    expect(trapName('SNMP trap from 192.0.2.5 (120 bytes)')).toBe('');
    expect(trapName('')).toBe('');
    expect(trapName(undefined)).toBe('');
  });
});
