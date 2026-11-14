import { useState } from 'react';

export interface NameField {
  value: string;
  setValue: (value: string) => void;
  trimmed: string;
  /** The current error, shown or not. */
  error: string | undefined;
  /** The error once the field was left, a save was tried or the name was taken. */
  shownError: string | undefined;
  touch: () => void;
  /** Records that the server answered 409 for the current name. */
  markTaken: () => void;
}

/**
 * A required name of at most `max` characters that is unique ignoring case
 * (tags, manufacturers, roles...). `taken` words the error for a name the
 * server said is in use.
 */
export function useNameField(initial: string, max: number, label: string, taken: (name: string) => string): NameField {
  const [value, setValue] = useState(initial);
  const [touched, setTouched] = useState(false);
  const [takenName, setTakenName] = useState<string | null>(null);
  const trimmed = value.trim();
  const error = !trimmed
    ? `${label} is required.`
    : trimmed.length > max
      ? `${label} must be ${max} characters or fewer.`
      : takenName === trimmed.toLowerCase()
        ? taken(trimmed)
        : undefined;
  return {
    value,
    setValue,
    trimmed,
    error,
    shownError: touched || takenName ? error : undefined,
    touch: () => setTouched(true),
    markTaken: () => setTakenName(trimmed.toLowerCase()),
  };
}
