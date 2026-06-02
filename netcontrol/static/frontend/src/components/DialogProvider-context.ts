import { createContext, type ReactNode, useContext } from 'react';

export interface ConfirmOptions {
  title?: string;
  message: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  confirmVariant?: 'danger' | 'primary';
}

export interface AlertOptions {
  title?: string;
  message: ReactNode;
  okLabel?: string;
  variant?: 'error' | 'default';
}

export interface DialogApi {
  /** Themed replacement for window.confirm — resolves true if confirmed. */
  confirm: (opts: ConfirmOptions | string) => Promise<boolean>;
  /** Themed replacement for window.alert — resolves once dismissed. */
  alert: (opts: AlertOptions | string) => Promise<void>;
}

export const DialogContext = createContext<DialogApi | null>(null);

export function useDialogs(): DialogApi {
  const ctx = useContext(DialogContext);
  if (!ctx) {
    throw new Error('useDialogs must be used within a <DialogProvider>');
  }
  return ctx;
}
