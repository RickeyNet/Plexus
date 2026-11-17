import { CustomDataError, toCustomDataError } from '@/api/customData';

/**
 * The per-field messages of a failed save: the `detail.fields` the server
 * sends with a 400 or 422 (a data validation rule, a bad device model id),
 * whether the request used `apiRequest` or `detailRequest`. `{}` otherwise.
 */
export function serverFieldErrors(err: unknown): Record<string, string> {
  const failure = toCustomDataError(err);
  return failure instanceof CustomDataError ? failure.fields : {};
}

/**
 * Splits server field errors into the ones a form shows under its own inputs
 * (`mapping`: server field name to form key; the first message per key wins)
 * and the rest.
 */
export function pickFieldErrors<K extends string>(
  fields: Record<string, string>,
  mapping: Partial<Record<string, K>>,
): { picked: Partial<Record<K, string>>; rest: Record<string, string> } {
  const picked: Partial<Record<K, string>> = {};
  const rest: Record<string, string> = {};
  for (const [field, message] of Object.entries(fields)) {
    const key = mapping[field];
    if (key === undefined) rest[field] = message;
    else if (picked[key] === undefined) picked[key] = message;
  }
  return { picked, rest };
}
