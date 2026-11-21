import { describe, expect, it } from 'vitest';

import { securityEventQuery } from '@/api/securityEvents';

import { actionBadge, addressPort, eventDevice, pageLabel, SECURITY_WINDOWS } from './securityEvents';

describe('security events', () => {
  it('says whether the traffic was blocked or only detected', () => {
    expect(actionBadge('blocked')).toEqual({ text: 'Blocked', tone: 'success' });
    expect(actionBadge('allowed')).toEqual({ text: 'Detected only', tone: 'warning' });
    expect(actionBadge('')).toEqual({ text: 'Detected only', tone: 'warning' });
    expect(actionBadge('rejected')).toEqual({ text: 'rejected', tone: 'neutral' });
  });

  it('joins an address and its port, IPv6 in brackets', () => {
    expect(addressPort('192.0.2.10', 443)).toBe('192.0.2.10:443');
    expect(addressPort('2001:db8::80', 443)).toBe('[2001:db8::80]:443');
    expect(addressPort('198.51.100.9', null)).toBe('198.51.100.9');
    expect(addressPort('', null)).toBe('-');
  });

  it('names the device by its host, else its source', () => {
    expect(eventDevice({ hostname: 'fw-edge-1.example.com', source_name: 'Edge', org_ref: 3 })).toBe(
      'fw-edge-1.example.com',
    );
    expect(eventDevice({ hostname: null, source_name: 'Edge', org_ref: 3 })).toBe('Edge');
    expect(eventDevice({ hostname: null, source_name: '', org_ref: 3 })).toBe('Source 3');
  });

  it('labels a page of the list', () => {
    expect(pageLabel(0, 100, 450)).toBe('Showing 1-100 of 450');
    expect(pageLabel(400, 50, 450)).toBe('Showing 401-450 of 450');
    expect(pageLabel(0, 0, 0)).toBe('0 of 0');
  });

  it('builds the list query without empty filters', () => {
    expect(securityEventQuery({ hours: 24 })).toBe('hours=24');
    expect(
      securityEventQuery({ hours: 1, severity: 'critical', action: 'blocked', q: ' beacon ', limit: 100, offset: 100 }),
    ).toBe('hours=1&severity=critical&action=blocked&q=beacon&limit=100&offset=100');
    expect(securityEventQuery({ hours: 168, q: '   ', offset: 0, hostId: 5 })).toBe('hours=168&host_id=5');
    expect(SECURITY_WINDOWS.map((w) => w.hours)).toEqual([1, 24, 168, 720]);
  });
});
