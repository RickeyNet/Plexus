import { ReactNode } from 'react';

import { Modal } from './Modal';

export interface AlertDialogProps {
  isOpen: boolean;
  title: string;
  message: ReactNode;
  okLabel?: string;
  variant?: 'error' | 'default';
  onClose: () => void;
}

export function AlertDialog({
  isOpen,
  title,
  message,
  okLabel = 'OK',
  variant = 'default',
  onClose,
}: AlertDialogProps) {
  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={title}
      size="small"
      footer={
        <button type="button" className="btn btn-primary" onClick={onClose} autoFocus>
          {okLabel}
        </button>
      }
    >
      <div className={variant === 'error' ? 'dialog-message dialog-message-error' : 'dialog-message'}>
        {message}
      </div>
    </Modal>
  );
}
