import { ReactNode } from 'react';

import { Modal } from './Modal';

export interface ConfirmDialogProps {
  isOpen: boolean;
  /** Names the action and its object: "Delete report schedule". */
  title: string;
  message: ReactNode;
  /** The verb the button carries out: "Delete", "Restore", "Cancel job". */
  confirmLabel: string;
  /**
   * Defaults to "Cancel". When the action being confirmed is itself a
   * cancellation, pass something that cannot be misread, e.g. "Keep running".
   */
  cancelLabel?: string;
  confirmVariant?: 'danger' | 'primary';
  loading?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmDialog({
  isOpen,
  title,
  message,
  confirmLabel,
  cancelLabel = 'Cancel',
  confirmVariant = 'danger',
  loading = false,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  return (
    <Modal
      isOpen={isOpen}
      onClose={() => {
        if (!loading) onCancel();
      }}
      title={title}
      size="small"
      footer={
        <>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={onCancel}
            disabled={loading}
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            className={`btn btn-${confirmVariant}`}
            onClick={onConfirm}
            disabled={loading}
            autoFocus
          >
            {loading ? `${confirmLabel}…` : confirmLabel}
          </button>
        </>
      }
    >
      <div className="dialog-message">{message}</div>
    </Modal>
  );
}
