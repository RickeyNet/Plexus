import { useEffect, useRef, useState } from 'react';

type CopyState = 'idle' | 'copied' | 'failed';

interface Props {
  /** The text to copy, or a function that builds it on click. */
  text: string | (() => string);
  label?: string;
  className?: string;
  disabled?: boolean;
  title?: string;
}

const FEEDBACK_MS = 1500;

/** A copy-to-clipboard button whose label confirms the copy, or reports that it failed. */
export function CopyButton({
  text,
  label = 'Copy',
  className = 'btn btn-sm btn-secondary',
  disabled,
  title,
}: Props) {
  const [state, setState] = useState<CopyState>('idle');
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => () => window.clearTimeout(timer.current), []);

  function handleClick() {
    const value = typeof text === 'function' ? text() : text;
    const settle = (next: CopyState) => {
      setState(next);
      window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => setState('idle'), FEEDBACK_MS);
    };
    // navigator.clipboard is undefined outside a secure context, so the call
    // sits inside the chain where that TypeError becomes a rejection.
    void Promise.resolve()
      .then(() => navigator.clipboard.writeText(value))
      .then(() => settle('copied'), () => settle('failed'));
  }

  return (
    <button type="button" className={className} onClick={handleClick} disabled={disabled} title={title}>
      <span aria-live="polite">
        {state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed' : label}
      </span>
    </button>
  );
}
