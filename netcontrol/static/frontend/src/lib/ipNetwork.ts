// IPv4 and IPv6 addresses and networks as numbers, for containment checks
// and numeric ordering ("10.0.0.0/24" before "10.0.0.128/25" before
// "10.0.1.0/24", which a text sort gets wrong for "10.0.10.0/24").

export interface IpNetwork {
  version: 4 | 6;
  /** The address as written, host bits included. */
  addr: bigint;
  /** Prefix length: 32 or 128 for a bare address. */
  len: number;
}

const V4_BITS = 32;
const V6_BITS = 128;

function bitsOf(version: 4 | 6): number {
  return version === 4 ? V4_BITS : V6_BITS;
}

function parseV4(text: string): bigint | null {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = (value << 8n) | BigInt(octet);
  }
  return value;
}

function parseV6(text: string): bigint | null {
  if (!text.includes(':') || !/^[0-9A-Fa-f:.]+$/.test(text)) return null;
  let head = text;
  // An embedded IPv4 tail ("::ffff:192.0.2.1") stands for the last two groups.
  let tail: bigint | null = null;
  const lastColon = text.lastIndexOf(':');
  if (text.includes('.')) {
    tail = parseV4(text.slice(lastColon + 1));
    if (tail === null) return null;
    head = text.slice(0, lastColon + 1);
    // "::192.0.2.1" leaves "::"; "64:ff9b::192.0.2.1" leaves "64:ff9b::".
    if (head.endsWith(':') && !head.endsWith('::')) head = head.slice(0, -1);
  }
  const groupsWanted = tail === null ? 8 : 6;
  const halves = head.split('::');
  if (halves.length > 2) return null;
  const split = (s: string) => (s === '' ? [] : s.split(':'));
  const left = split(halves[0]);
  const right = halves.length === 2 ? split(halves[1]) : [];
  const missing = groupsWanted - left.length - right.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
  const groups = [...left, ...Array<string>(halves.length === 2 ? missing : 0).fill('0'), ...right];
  let value = 0n;
  for (const group of groups) {
    if (!/^[0-9A-Fa-f]{1,4}$/.test(group)) return null;
    value = (value << 16n) | BigInt(parseInt(group, 16));
  }
  return tail === null ? value : (value << 32n) | tail;
}

/** An IPv4/IPv6 address ("192.0.2.1") or network ("192.0.2.0/24"); null for anything else. */
export function parseIpNetwork(text: string | null | undefined): IpNetwork | null {
  const trimmed = (text ?? '').trim();
  if (!trimmed) return null;
  const slash = trimmed.indexOf('/');
  const addrText = slash < 0 ? trimmed : trimmed.slice(0, slash);
  const lenText = slash < 0 ? null : trimmed.slice(slash + 1);
  if (lenText !== null && !/^\d{1,3}$/.test(lenText)) return null;
  const v4 = parseV4(addrText);
  const version: 4 | 6 = v4 === null ? 6 : 4;
  const addr = v4 ?? parseV6(addrText);
  if (addr === null) return null;
  const bits = bitsOf(version);
  const len = lenText === null ? bits : Number(lenText);
  if (len > bits) return null;
  return { version, addr, len };
}

/** The network part of `addr` under a `len`-bit prefix (host bits dropped). */
function networkBits(addr: bigint, len: number, bits: number): bigint {
  return addr >> BigInt(bits - len);
}

/** Whether `outer` contains `inner` (a network contains itself). */
export function networkContains(outer: IpNetwork, inner: IpNetwork): boolean {
  if (outer.version !== inner.version || outer.len > inner.len) return false;
  const bits = bitsOf(outer.version);
  return networkBits(outer.addr, outer.len, bits) === networkBits(inner.addr, outer.len, bits);
}

/** Whether the two ranges share any address: one contains the other. */
export function networksOverlap(a: IpNetwork, b: IpNetwork): boolean {
  return networkContains(a, b) || networkContains(b, a);
}

/**
 * Ascending order for address or CIDR strings: IPv4 before IPv6, then by
 * address, then wider prefixes first. Text that does not parse sorts after
 * every address, in text order.
 */
export function compareIpText(a: string | null | undefined, b: string | null | undefined): number {
  const x = parseIpNetwork(a);
  const y = parseIpNetwork(b);
  if (x && y) {
    if (x.version !== y.version) return x.version - y.version;
    if (x.addr !== y.addr) return x.addr < y.addr ? -1 : 1;
    return x.len - y.len;
  }
  if (x) return -1;
  if (y) return 1;
  return (a ?? '').localeCompare(b ?? '');
}
