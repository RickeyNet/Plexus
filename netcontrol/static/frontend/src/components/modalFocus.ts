// Focus-trap helpers for <Modal>, kept apart from Modal.tsx so they can be
// unit tested (component files may only export components).

/** Elements a Tab press can land on inside a dialog. */
export const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[contenteditable="true"]',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

/**
 * Where a Tab press must be redirected to keep focus inside a dialog with
 * `count` focusable elements, or null when the browser's own Tab order
 * already stays inside. `current` is the index of the focused element, -1
 * when focus is on the dialog box itself or outside it.
 *
 * Returns 'self' when there is nothing focusable, so the caller keeps focus
 * on the dialog box.
 */
export function trapTabTarget(current: number, count: number, shiftKey: boolean): number | 'self' | null {
  if (count <= 0) return 'self';
  if (current < 0) return shiftKey ? count - 1 : 0;
  if (shiftKey && current === 0) return count - 1;
  if (!shiftKey && current === count - 1) return 0;
  return null;
}

/**
 * True when a backdrop click should close the modal: the press and the
 * release must both land on the backdrop. A text-selection drag that starts
 * inside the dialog and ends on the backdrop is not a close.
 */
export function isBackdropDismiss(pressedOnBackdrop: boolean, releasedOnBackdrop: boolean): boolean {
  return pressedOnBackdrop && releasedOnBackdrop;
}
