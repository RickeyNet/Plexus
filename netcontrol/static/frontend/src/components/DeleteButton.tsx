import type { MouseEvent, ReactNode } from 'react';

export interface DeleteButtonProps {
  onClick: (event: MouseEvent<HTMLButtonElement>) => void;
  /** Button text; defaults to "Delete". Use "Remove" for unlinking rather than destroying. */
  label?: ReactNode;
  /** `sm` (default) for table rows and card headers, `xs` for dense inline lists, `md` for dialogs and forms. */
  size?: 'xs' | 'sm' | 'md';
  disabled?: boolean;
  /** The delete is in flight: disables the button and shows "Deleting…". */
  busy?: boolean;
  /** Tooltip; also the accessible name when `aria-label` is not given. */
  title?: string;
  /** Accessible name, e.g. "Delete profile Core baseline", when the label alone is ambiguous in a list. */
  'aria-label'?: string;
  className?: string;
}

const SIZE_CLASS = { xs: ' btn-xs', sm: ' btn-sm', md: '' } as const;

/**
 * The one delete button: `.btn.btn-danger`, a danger-tinted button no louder
 * than the secondary Edit button beside it. It only renders the button; the
 * caller confirms (useDialogs().confirm / ConfirmDialog) before deleting.
 */
export function DeleteButton({
  onClick,
  label = 'Delete',
  size = 'sm',
  disabled,
  busy,
  title,
  className,
  ...rest
}: DeleteButtonProps) {
  return (
    <button
      type="button"
      className={`btn btn-danger${SIZE_CLASS[size]}${className ? ` ${className}` : ''}`}
      onClick={onClick}
      disabled={disabled || busy}
      title={title}
      aria-label={rest['aria-label']}
      aria-busy={busy || undefined}
    >
      {busy ? 'Deleting…' : label}
    </button>
  );
}
