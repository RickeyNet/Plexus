// Shared backend-timestamp handling.
//
// The backend returns naive UTC timestamps ("YYYY-MM-DD HH:MM:SS", no zone) in
// many places. Passing those straight to `new Date(...)` parses them as *local*
// time, shifting every displayed time by the browser's UTC offset. Funnel all
// backend timestamps through these helpers so they are read as UTC.

// True when a string already carries a timezone suffix (Z or ±HH:MM).
function hasTimezone(s: string): boolean {
  return /Z$|[+-]\d{2}:?\d{2}$/.test(s);
}

export function parseBackendDate(isoStr: string | null | undefined): Date | null {
  if (!isoStr) return null;
  // Normalize a space separator to 'T' (so every browser parses it), then
  // append 'Z' when no zone is present so it is read as UTC, not local.
  const spaced = isoStr.includes('T') ? isoStr : isoStr.replace(' ', 'T');
  const normalized = hasTimezone(spaced) ? spaced : `${spaced}Z`;
  const d = new Date(normalized);
  return Number.isNaN(d.getTime()) ? null : d;
}

// Locale date+time for display; falls back to the raw value (or a dash) when
// the timestamp is missing/unparseable.
export function formatBackendDateTime(
  isoStr: string | null | undefined,
  fallback = '-',
): string {
  const d = parseBackendDate(isoStr);
  if (d) return d.toLocaleString();
  return isoStr || fallback;
}

// Locale date-only for display.
export function formatBackendDate(
  isoStr: string | null | undefined,
  fallback = '-',
): string {
  const d = parseBackendDate(isoStr);
  if (d) return d.toLocaleDateString();
  return isoStr || fallback;
}
