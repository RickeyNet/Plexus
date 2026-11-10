import type { ReactNode } from 'react';

export interface FieldErrorProps {
  /** Referenced by the field's `aria-describedby`. */
  id?: string;
  /** The message; renders nothing when empty. */
  children?: ReactNode;
}

/**
 * The one inline validation message: a line of danger-coloured text under the
 * field it describes (`.form-error`). Use it instead of a pop-up `alert()`
 * for anything the user can fix in the form. Pair it with
 * `aria-invalid={!!error}` on the input, which turns the border red.
 *
 * A message that is not about a single field (a failed save) belongs in a
 * `<Callout tone="danger">` above the form instead.
 */
export function FieldError({ id, children }: FieldErrorProps) {
  if (children === undefined || children === null || children === false || children === '') return null;
  return (
    <div id={id} className="form-error" role="alert">
      {children}
    </div>
  );
}
