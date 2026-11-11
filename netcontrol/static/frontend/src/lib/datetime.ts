// Shared backend-timestamp handling and the one display format per kind.
//
// The backend returns timestamps in a few shapes, all UTC:
//   - naive "YYYY-MM-DD HH:MM:SS" (no zone),
//   - Python isoformat "YYYY-MM-DDTHH:MM:SS.ffffff+00:00",
//   - Postgres text "YYYY-MM-DD HH:MM:SS.ffffff+00" (a TEXT column filled by
//     NOW(); the offset has hours only).
// Passing a naive value straight to `new Date(...)` parses it as *local* time,
// shifting every displayed time by the browser's UTC offset, and the short
// "+00" offset is rejected outright once the separator is a 'T'. Funnel all
// backend timestamps through these helpers so they are read as UTC.

/** A backend timestamp string, epoch milliseconds, or a Date. */
export type DateInput = string | number | Date | null | undefined;

// A trailing zone: Z, ±HH, ±HHMM or ±HH:MM, after a time of day (so the
// "-07" day of a date-only "2026-07-07" is not mistaken for an offset).
const ZONE_RE = /\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(Z|[+-]\d{2}(?::?\d{2})?)$/i;
const DATE_ONLY_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

export function parseBackendDate(isoStr: string | null | undefined): Date | null {
  if (!isoStr) return null;
  const text = isoStr.trim();
  // A bare calendar date is a day, not an instant: keep it on the same
  // calendar day in every timezone (UTC midnight would show the previous day
  // west of Greenwich).
  const day = DATE_ONLY_RE.exec(text);
  if (day) {
    const d = new Date(Number(day[1]), Number(day[2]) - 1, Number(day[3]));
    return Number.isNaN(d.getTime()) ? null : d;
  }
  // Normalize a space separator to 'T' (so every browser parses it), widen a
  // short "+00" offset to "+00:00", and append 'Z' when no zone is present so
  // the value is read as UTC, not local.
  let normalized = text.includes('T') ? text : text.replace(' ', 'T');
  const zone = ZONE_RE.exec(normalized);
  if (!zone) {
    normalized = `${normalized}Z`;
  } else if (/^[+-]\d{2}$/.test(zone[1])) {
    normalized = `${normalized}:00`;
  }
  const d = new Date(normalized);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** Any DateInput as a valid Date, or null. Strings go through parseBackendDate. */
export function toDate(value: DateInput): Date | null {
  if (value == null || value === '') return null;
  if (typeof value === 'string') return parseBackendDate(value);
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

// One display format per kind. Locale (and so 12/24 hour and field order) is
// the viewer's; only the fields shown are fixed.
const DATE_OPTS: Intl.DateTimeFormatOptions = { year: 'numeric', month: 'short', day: 'numeric' };
const DATE_TIME_OPTS: Intl.DateTimeFormatOptions = { ...DATE_OPTS, hour: 'numeric', minute: '2-digit' };
const TIMESTAMP_OPTS: Intl.DateTimeFormatOptions = { ...DATE_TIME_OPTS, second: '2-digit' };
const TIME_OPTS: Intl.DateTimeFormatOptions = { hour: 'numeric', minute: '2-digit', second: '2-digit' };

function format(value: DateInput, fallback: string, opts: Intl.DateTimeFormatOptions): string {
  const d = toDate(value);
  if (d) return d.toLocaleString(undefined, opts);
  // An unparseable string is shown as-is rather than hidden.
  return typeof value === 'string' && value ? value : fallback;
}

/** Date and time to the minute ("Jul 7, 2026, 12:00 PM"): table cells, "last scan", "created". */
export function formatBackendDateTime(value: DateInput, fallback = '-'): string {
  return format(value, fallback, DATE_TIME_OPTS);
}

/** Date and time to the second ("Jul 7, 2026, 12:00:05 PM"): log lines, events, audit entries. */
export function formatBackendTimestamp(value: DateInput, fallback = '-'): string {
  return format(value, fallback, TIMESTAMP_OPTS);
}

/** Calendar date only ("Jul 7, 2026"). */
export function formatBackendDate(value: DateInput, fallback = '-'): string {
  return format(value, fallback, DATE_OPTS);
}

/** Time of day only, to the second ("12:00:05 PM"): stream/output lines within one run. */
export function formatBackendTime(value: DateInput, fallback = '-'): string {
  return format(value, fallback, TIME_OPTS);
}

/**
 * Coarse span from `now` to `value`, at most two units: "just now", "45m ago",
 * "1d 2h ago", "in 2h 15m", "in <1m". `now` is injectable for tests.
 */
export function formatRelativeTime(value: DateInput, now: number = Date.now(), fallback = '-'): string {
  const d = toDate(value);
  if (!d) return typeof value === 'string' && value ? value : fallback;
  const delta = d.getTime() - now;
  if (Math.abs(delta) < 60_000) return delta < 0 ? 'just now' : 'in <1m';
  const past = delta < 0;
  let secs = Math.floor(Math.abs(delta) / 1000);
  const days = Math.floor(secs / 86_400);
  secs -= days * 86_400;
  const hours = Math.floor(secs / 3_600);
  secs -= hours * 3_600;
  const mins = Math.floor(secs / 60);
  const parts: string[] = [];
  if (days) parts.push(`${days}d`);
  if (hours) parts.push(`${hours}h`);
  if (!days && mins) parts.push(`${mins}m`);
  const span = parts.slice(0, 2).join(' ') || '<1m';
  return past ? `${span} ago` : `in ${span}`;
}

/**
 * The value of an `<input type="datetime-local">` ("YYYY-MM-DDTHH:MM", the
 * viewer's local time) for an instant; '' when missing or unparseable.
 */
export function toLocalInputValue(value: DateInput): string {
  const d = toDate(value);
  if (!d) return '';
  const pad = (n: number) => String(n).padStart(2, '0');
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
    `T${pad(d.getHours())}:${pad(d.getMinutes())}`
  );
}

/**
 * A datetime-local input value (the viewer's local time) as a UTC ISO string
 * for the API; '' when empty or unparseable.
 */
export function localInputToIso(value: string | null | undefined): string {
  if (!value) return '';
  // No zone on purpose: the input is local time, so it must not go through
  // parseBackendDate (which reads zone-less values as UTC).
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? '' : d.toISOString();
}

/**
 * A schedule interval in seconds as its largest whole unit: 86400 -> "1d",
 * 21600 -> "6h", 900 -> "15m", 45 -> "45s". Missing or zero is "-".
 */
export function formatInterval(seconds: number | null | undefined): string {
  if (!seconds) return '-';
  if (seconds % 86400 === 0) return `${seconds / 86400}d`;
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}
