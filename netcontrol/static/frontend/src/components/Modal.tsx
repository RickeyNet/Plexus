import { ReactNode, useEffect } from 'react';
import { createPortal } from 'react-dom';

// Module-level stack so multiple open Modals cooperate: only the topmost
// (most recently opened) handles Escape. Without this, every Modal listens
// on document and a single Escape keypress closes all of them.
const escapeStack: Array<() => void> = [];

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
  useEffect(() => {
    if (!isOpen) return;
    escapeStack.push(onClose);
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      const top = escapeStack[escapeStack.length - 1];
      if (top === onClose) {
        e.stopPropagation();
        onClose();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
      const idx = escapeStack.lastIndexOf(onClose);
      if (idx >= 0) escapeStack.splice(idx, 1);
    };
  }, [isOpen, onClose]);

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
