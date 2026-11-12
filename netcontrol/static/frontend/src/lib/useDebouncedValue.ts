import { useEffect, useState } from 'react';

/**
 * `value` once it has stopped changing for `delayMs`, so a box that queries
 * the server as it is typed in does not send a request per keystroke.
 */
export function useDebouncedValue<T>(value: T, delayMs = 250): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(timer);
  }, [value, delayMs]);
  return debounced;
}
