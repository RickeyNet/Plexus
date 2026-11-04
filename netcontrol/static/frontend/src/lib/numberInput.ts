/**
 * Parse the text of a number field into an integer clamped to [min, max].
 *
 * Number inputs should hold their raw text in state so the field can be
 * cleared and retyped; coercing on every keystroke (`Number(v) || default`)
 * snaps an empty field back to the default and makes it impossible to edit.
 * Call this when the value is consumed (submit), not on change.
 */
export function parseBoundedInt(
  text: string,
  min: number,
  max: number,
  fallback: number,
): number {
  const n = Number.parseInt(text.trim(), 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}
