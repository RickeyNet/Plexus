import { useCallback, useEffect, useRef, useState } from 'react';

export interface FlashMessage {
  kind: 'success' | 'error';
  text: string;
}

/**
 * A short-lived action result ("Settings saved", "Pull failed: ..."): `flash`
 * shows it and clears it after `timeoutMs`; a new flash restarts the timer.
 * Render it as a Callout next to the control that started the action.
 */
export function useFlashMessage(timeoutMs = 8000) {
  const [message, setMessage] = useState<FlashMessage | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => {
    if (timerRef.current) clearTimeout(timerRef.current);
  }, []);

  const flash = useCallback(
    (kind: FlashMessage['kind'], text: string) => {
      if (timerRef.current) clearTimeout(timerRef.current);
      setMessage({ kind, text });
      timerRef.current = setTimeout(() => {
        timerRef.current = null;
        setMessage(null);
      }, timeoutMs);
    },
    [timeoutMs],
  );

  return { message, flash };
}
