import { ReactNode, useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';

// Module-level stack so multiple open Modals cooperate: only the topmost
// (most recently opened) handles Escape. Without this, every Modal listens
// on document and a single Escape keypress closes all of them.
//
// Entries are stable per-instance symbols, NOT the onClose callback. Keying on
// onClose meant any parent re-render (e.g. the Jobs page's 15s poll) gave a new
// callback identity, which popped the modal and re-pushed it on top — reordering
// the stack so Escape closed the wrong (outer) modal.
const escapeStack: Array<symbol> = [];

/**
 * Portal-based modal that renders into document.body and uses the legacy
 * SPA's ``.modal-overlay`` / ``.modal`` styles so the React app matches the
 * vanilla SPA visually.
 *
 * Closes on:
 *   * Clicking the backdrop (anywhere outside the .modal box)
 *   * Pressing Escape
 *   * Clicking the × button in the header
 */
export interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title?: string;
  children: ReactNode;
  size?: 'default' | 'large';
}

export function Modal({ isOpen, onClose, title, children, size = 'default' }: ModalProps) {
  // Latest onClose without making it an effect dependency, so a parent
  // re-render can't churn the escape-stack ordering.
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  // Stable identity for this modal instance's escape-stack entry.
  const tokenRef = useRef<symbol | null>(null);
  if (tokenRef.current === null) tokenRef.current = Symbol('modal');

  useEffect(() => {
    if (!isOpen) return;
    const token = tokenRef.current!;
    escapeStack.push(token);
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      if (escapeStack[escapeStack.length - 1] === token) {
        e.stopPropagation();
        onCloseRef.current();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
      const idx = escapeStack.lastIndexOf(token);
      if (idx >= 0) escapeStack.splice(idx, 1);
    };
  }, [isOpen]);

  if (!isOpen) return null;

  return createPortal(
    <div
      className="modal-overlay active"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
      role="presentation"
    >
      <div
        className={size === 'large' ? 'modal modal-large' : 'modal'}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        {title !== undefined && (
          <div className="modal-header">
            <h3>{title}</h3>
            <button
              type="button"
              className="modal-close"
              onClick={onClose}
              aria-label="Close"
            >
              ×
            </button>
          </div>
        )}
        <div className="modal-body">{children}</div>
      </div>
    </div>,
    document.body,
  );
}
