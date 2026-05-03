import { ReactNode, useEffect } from 'react';
import { createPortal } from 'react-dom';

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
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
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
