import type { Tone } from '@/lib/severity';

/**
 * Badge tones of an APC UPS's PowerNet-MIB state codes. The code sets match
 * the server's alert classes (netcontrol/integrations/apc/snmp.py): on
 * battery is a warning, off or on bypass is not protecting the load.
 */
const OUTPUT_ON_BATTERY = new Set([3]);
const OUTPUT_UNPROTECTED = new Set([5, 6, 7, 9, 10, 11, 16]);
const OUTPUT_ONLINE = new Set([2, 4, 12, 13, 20]);
const BATTERY_PROBLEMS = new Set([3, 4, 5]);

/** upsBasicOutputStatus → tone. */
export function upsOutputTone(code: number | null | undefined): Tone {
  if (code == null) return 'neutral';
  if (OUTPUT_UNPROTECTED.has(code)) return 'danger';
  if (OUTPUT_ON_BATTERY.has(code)) return 'warning';
  if (OUTPUT_ONLINE.has(code)) return 'success';
  return 'neutral';
}

/** upsBasicBatteryStatus (and the replace indicator) → tone. */
export function upsBatteryTone(code: number | null | undefined, needsReplacing?: boolean): Tone {
  if (code != null && BATTERY_PROBLEMS.has(code)) return 'danger';
  if (needsReplacing) return 'warning';
  if (code === 2) return 'success';
  return 'neutral';
}

/** A reading with its unit ("229.8 V"), "N/A" when the UPS did not report it. */
export function unit(value: number | null | undefined, suffix: string): string {
  return value != null ? `${value} ${suffix}` : 'N/A';
}

/** Input voltage and frequency as "231.2 V, 49.9 Hz" (either may be missing). */
export function formatPower(volts: number | null | undefined, hertz: number | null | undefined): string {
  const parts = [volts != null && unit(volts, 'V'), hertz != null && unit(hertz, 'Hz')].filter(Boolean);
  return parts.length ? parts.join(', ') : 'N/A';
}

/** Minutes of runtime as "1 h 05 min" / "23 min", "N/A" when unknown. */
export function formatRuntime(minutes: number | null | undefined): string {
  if (minutes == null) return 'N/A';
  const whole = Math.round(minutes);
  if (whole < 60) return `${whole} min`;
  const h = Math.floor(whole / 60);
  const m = whole % 60;
  return `${h} h ${String(m).padStart(2, '0')} min`;
}
