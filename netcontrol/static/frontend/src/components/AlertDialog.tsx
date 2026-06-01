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
    <Modal isOpen={isOpen} onClose={onClose} title={title}>
      <p
        style={{
          margin: '0 0 1rem',
          color: variant === 'error' ? 'var(--danger)' : undefined,
        }}
      >
        {message}
      </p>
      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <button type="button" className="btn btn-primary" onClick={onClose} autoFocus>
          {okLabel}
        </button>
      </div>
    </Modal>
  );
}
