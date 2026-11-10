import type { ButtonHTMLAttributes } from 'react';

export interface BusyButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  /** True while the action this button started is in flight. */
  busy: boolean;
  /** Replaces the label while busy ("Saving…"). Defaults to the normal label. */
  busyLabel?: string;
}

/**
 * A button for an async action: while `busy` it is disabled, shows a
 * spinner and reports `aria-busy`, so a second click cannot fire the
 * action again. Pass the usual `btn …` classes in `className`.
 */
export function BusyButton({ busy, busyLabel, disabled, children, type = 'button', ...rest }: BusyButtonProps) {
  return (
    <button {...rest} type={type} disabled={busy || disabled} aria-busy={busy || undefined}>
      {busy && <span className="backup-spinner" aria-hidden="true" />}
      {busy && busyLabel ? busyLabel : children}
    </button>
  );
}
