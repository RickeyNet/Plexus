import { ReactNode, useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';

import { FOCUSABLE_SELECTOR, isBackdropDismiss, trapTabTarget } from './modalFocus';

// Module-level stack so multiple open Modals cooperate: only the topmost
// (most recently opened) handles Escape and traps Tab. Without this, every
// Modal listens on document and a single Escape keypress closes all of them.
//
// Entries are stable per-instance symbols, NOT the onClose callback. Keying on
// onClose meant any parent re-render (e.g. the Jobs page's 15s poll) gave a new
// callback identity, which popped the modal and re-pushed it on top — reordering
// the stack so Escape closed the wrong (outer) modal.
const escapeStack: Array<symbol> = [];

export type ModalSize = 'small' | 'default' | 'medium' | 'large';

const SIZE_CLASS: Record<ModalSize, string> = {
  small: 'modal modal-small',
  default: 'modal',
  medium: 'modal modal-medium',
  large: 'modal modal-large',
};

/**
 * Portal-based modal that renders into document.body with the
 * ``.modal-overlay`` / ``.modal`` styles.
 *
 * Layout: the header (title and ×) and the footer stay put; only the body
 * scrolls. Pass action buttons through ``footer`` so they never scroll out of
 * view: Cancel (``btn btn-secondary``) first, the primary action last. A
 * submit button in the footer sits outside the ``<form>``, so give the form
 * an id (``useId()``) and the button ``form={id}``.
 *
 * Sizes: ``small`` (480px) for confirms and one- or two-field prompts,
 * ``default`` (700px) for forms, ``medium`` (1000px) for two-column forms and
 * modest tables, ``large`` (1600px) for wide tables, diffs and log viewers.
 *
 * Closes on Escape, the × button, or a click that both starts and ends on
 * the backdrop. ``dismissible={false}`` turns all three off and hides the ×.
 *
 * Focus moves into the dialog on open (an ``autoFocus`` element wins, else
 * the first control in the body), Tab cycles inside it, and focus returns to
 * the element that had it when the modal closes.
 */
export interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title?: string;
  children: ReactNode;
  size?: ModalSize;
  /** Action row pinned under the scrolling body. */
  footer?: ReactNode;
  /** False for a modal the user must complete: no ×, Escape or backdrop close. */
  dismissible?: boolean;
}

export function Modal({
  isOpen,
  onClose,
  title,
  children,
  size = 'default',
  footer,
  dismissible = true,
}: ModalProps) {
  // Latest onClose/dismissible without making them effect dependencies, so a
  // parent re-render can't churn the escape-stack ordering. Synced in a
  // dep-less effect rather than during render; the keydown handler only reads
  // them at event time, after effects have run.
  const onCloseRef = useRef(onClose);
  const dismissibleRef = useRef(dismissible);
  useEffect(() => {
    onCloseRef.current = onClose;
    dismissibleRef.current = dismissible;
  });
  // Stable identity for this modal instance's escape-stack entry.
  const tokenRef = useRef<symbol | null>(null);
  if (tokenRef.current === null) tokenRef.current = Symbol('modal');

  const dialogRef = useRef<HTMLDivElement | null>(null);
  // Whether the current mouse press began on the backdrop itself.
  const pressedOnBackdropRef = useRef(false);

  useEffect(() => {
    if (!isOpen) return;
    const token = tokenRef.current!;
    escapeStack.push(token);

    const focusables = (): HTMLElement[] => {
      const dialog = dialogRef.current;
      if (!dialog) return [];
      return Array.from(dialog.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
        // Skip controls inside display:none containers (inactive tab panels).
        (el) => el.getClientRects().length > 0,
      );
    };

    // Initial focus. React has already honoured any autoFocus by now; if
    // nothing inside the dialog took focus, prefer the first body control
    // over the × so a form is ready to type into.
    const restoreTo = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const dialog = dialogRef.current;
    if (dialog && !dialog.contains(document.activeElement)) {
      const all = focusables();
      const first = all.find((el) => !el.classList.contains('modal-close')) ?? all[0];
      (first ?? dialog).focus();
    }

    const onKey = (e: KeyboardEvent) => {
      if (escapeStack[escapeStack.length - 1] !== token) return;
      if (e.key === 'Escape') {
        if (!dismissibleRef.current) return;
        e.stopPropagation();
        onCloseRef.current();
        return;
      }
      if (e.key !== 'Tab') return;
      const box = dialogRef.current;
      if (!box) return;
      const all = focusables();
      const current = all.indexOf(document.activeElement as HTMLElement);
      // Focus inside the dialog but on something the selector does not list
      // (a third-party widget's internals): leave the browser's Tab alone.
      if (current < 0 && box.contains(document.activeElement) && document.activeElement !== box) return;
      const target = trapTabTarget(current, all.length, e.shiftKey);
      if (target === null) return;
      e.preventDefault();
      (target === 'self' ? box : all[target]).focus();
    };
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
      const idx = escapeStack.lastIndexOf(token);
      if (idx >= 0) escapeStack.splice(idx, 1);
      if (restoreTo && restoreTo.isConnected) restoreTo.focus();
    };
  }, [isOpen]);

  if (!isOpen) return null;

  return createPortal(
    <div
      className="modal-overlay active"
      onMouseDown={(e) => {
        pressedOnBackdropRef.current = e.target === e.currentTarget;
      }}
      onClick={(e) => {
        const dismiss = isBackdropDismiss(pressedOnBackdropRef.current, e.target === e.currentTarget);
        pressedOnBackdropRef.current = false;
        if (dismiss && dismissible) onClose();
      }}
      role="presentation"
    >
      <div
        ref={dialogRef}
        className={SIZE_CLASS[size]}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
      >
        {title !== undefined && (
          <div className="modal-header">
            <h3>{title}</h3>
            {dismissible && (
              <button
                type="button"
                className="modal-close"
                onClick={onClose}
                aria-label="Close"
              >
                ×
              </button>
            )}
          </div>
        )}
        <div className="modal-body">{children}</div>
        {footer !== undefined && footer !== null && footer !== false && (
          <div className="modal-footer">{footer}</div>
        )}
      </div>
    </div>,
    document.body,
  );
}
