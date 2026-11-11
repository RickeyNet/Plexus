/** Above this a count no longer fits a stat tile with separators (and is past exact integers). */
const SCIENTIFIC_FROM = 1e15;

/**
 * A count with thousands separators: 65536 -> "65,536". Counts too large to
 * show in full (an IPv6 /64 holds 1.8e19 addresses) use scientific notation:
 * "1.84E19". Missing or non-numeric values read as 0.
 */
export function formatCount(value: unknown): string {
  const n = Number(value ?? 0);
  if (!Number.isFinite(n)) return '0';
  if (Math.abs(n) >= SCIENTIFIC_FROM) {
    return n.toLocaleString(undefined, { notation: 'scientific', maximumFractionDigits: 2 });
  }
  return n.toLocaleString();
}
