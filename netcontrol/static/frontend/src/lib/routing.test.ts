import { describe, expect, it } from 'vitest';

import {
  complianceStateHelp,
  complianceStateLabel,
  complianceStateTone,
  formatAsn,
  ipVersion,
  parseAsn,
  peeringAddressErrors,
  routerIdError,
  statusLabel,
  statusTone,
} from './routing';

describe('parseAsn', () => {
  it('reads asplain, AS-prefixed and asdot numbers', () => {
    expect(parseAsn('65001')).toBe(65001);
    expect(parseAsn(' AS64512 ')).toBe(64512);
    expect(parseAsn('as65000')).toBe(65000);
    expect(parseAsn('1.10')).toBe(65546);
    expect(parseAsn('4294967295')).toBe(4294967295);
  });

  it('refuses numbers out of range and anything else', () => {
    for (const bad of ['', '0', '-1', '4294967296', '65001x', '1.2.3', '70000.1', 'AS']) {
      expect(parseAsn(bad)).toBeNull();
    }
  });

  it('formats', () => {
    expect(formatAsn(65001)).toBe('AS65001');
    expect(formatAsn(null)).toBe('-');
  });
});

describe('addresses', () => {
  it('knows the family of a bare address', () => {
    expect(ipVersion('192.0.2.1')).toBe(4);
    expect(ipVersion('2001:db8::1')).toBe(6);
    expect(ipVersion('192.0.2.0/24')).toBeNull();
    expect(ipVersion('192.0.2.300')).toBeNull();
    expect(ipVersion('edge-r1')).toBeNull();
  });

  it('checks a peering address pair', () => {
    expect(peeringAddressErrors('', '192.0.2.2')).toEqual({});
    expect(peeringAddressErrors('192.0.2.1', '192.0.2.2')).toEqual({});
    expect(peeringAddressErrors('', '')).toEqual({ remote: 'Remote address is required.' });
    expect(peeringAddressErrors('x', 'y').remote).toMatch(/IPv4 or IPv6/);
    expect(peeringAddressErrors('x', '192.0.2.2').local).toMatch(/Local address/);
    expect(peeringAddressErrors('192.0.2.1', '2001:db8::2').local).toMatch(/both be IPv4/);
  });

  it('checks a router id', () => {
    expect(routerIdError('')).toBeUndefined();
    expect(routerIdError('192.0.2.1')).toBeUndefined();
    expect(routerIdError('2001:db8::1')).toMatch(/IPv4/);
  });
});

describe('labels and tones', () => {
  it('names compliance states', () => {
    expect(complianceStateLabel('asn_mismatch')).toBe('ASN mismatch');
    expect(complianceStateLabel('no_data')).toBe('No data');
    expect(complianceStateLabel('other')).toBe('other');
    expect(complianceStateTone('matched')).toBe('success');
    expect(complianceStateTone('down')).toBe('danger');
    expect(complianceStateTone('other')).toBe('neutral');
    expect(complianceStateHelp('missing')).toMatch(/not among/);
    expect(complianceStateHelp('other')).toBe('');
  });

  it('names statuses', () => {
    expect(statusLabel('planned')).toBe('Planned');
    expect(statusLabel('')).toBe('-');
    expect(statusTone('active')).toBe('success');
    expect(statusTone('weird')).toBe('neutral');
  });
});
