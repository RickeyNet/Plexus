import { describe, expect, it } from 'vitest';

import { compareIpText, networkContains, networksOverlap, parseIpNetwork } from './ipNetwork';

describe('parseIpNetwork', () => {
  it('reads IPv4 addresses and networks', () => {
    expect(parseIpNetwork('192.0.2.1')).toEqual({ version: 4, addr: 0xc0000201n, len: 32 });
    expect(parseIpNetwork(' 192.0.2.0/24 ')).toEqual({ version: 4, addr: 0xc0000200n, len: 24 });
    expect(parseIpNetwork('0.0.0.0/0')).toEqual({ version: 4, addr: 0n, len: 0 });
  });

  it('reads IPv6, compressed and with an IPv4 tail', () => {
    expect(parseIpNetwork('2001:db8::1')?.addr).toBe(0x20010db8000000000000000000000001n);
    expect(parseIpNetwork('2001:db8::/32')).toMatchObject({ version: 6, len: 32 });
    expect(parseIpNetwork('::')?.addr).toBe(0n);
    expect(parseIpNetwork('::ffff:192.0.2.1')?.addr).toBe(0xffffc0000201n);
    expect(parseIpNetwork('1:2:3:4:5:6:7:8')?.addr).toBe(0x00010002000300040005000600070008n);
  });

  it('rejects text that is not an address', () => {
    for (const bad of ['', '10.1.', '256.0.0.1', '192.0.2.0/33', '2001:db8::/129', '1::2::3', '1:2:3:4:5:6:7:8:9', 'core-sw1', '192.0.2.0/x']) {
      expect(parseIpNetwork(bad), bad).toBeNull();
    }
  });
});

describe('networkContains / networksOverlap', () => {
  const net = (t: string) => parseIpNetwork(t)!;

  it('finds an address inside its subnet', () => {
    expect(networkContains(net('192.0.2.0/24'), net('192.0.2.77'))).toBe(true);
    expect(networkContains(net('192.0.2.0/24'), net('192.0.3.1'))).toBe(false);
    expect(networkContains(net('2001:db8::/32'), net('2001:db8:1::5'))).toBe(true);
  });

  it('ignores host bits on the outer network and never mixes versions', () => {
    expect(networkContains(net('192.0.2.9/24'), net('192.0.2.200'))).toBe(true);
    expect(networkContains(net('0.0.0.0/0'), net('::1'))).toBe(false);
  });

  it('overlaps either way round', () => {
    expect(networksOverlap(net('198.51.100.0/25'), net('198.51.100.0/24'))).toBe(true);
    expect(networksOverlap(net('198.51.100.0/24'), net('198.51.100.0/25'))).toBe(true);
    expect(networksOverlap(net('198.51.100.0/25'), net('198.51.100.128/25'))).toBe(false);
  });
});

describe('compareIpText', () => {
  it('orders numerically, IPv4 first, wider prefixes first, text last', () => {
    const sorted = ['zz', '2001:db8::/64', '10.0.10.0/24', '10.0.2.0/24', '10.0.2.0/23', 'aa'].sort(compareIpText);
    expect(sorted).toEqual(['10.0.2.0/23', '10.0.2.0/24', '10.0.10.0/24', '2001:db8::/64', 'aa', 'zz']);
  });
});
