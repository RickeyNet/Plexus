import { createContext, type ReactNode, useContext } from 'react';

export interface ConfirmOptions {
  /** Names the action and its object: "Delete report schedule". */
  title: string;
  /** What will happen. Line breaks in a string are kept. */
  message: ReactNode;
  /** The verb the button carries out: "Delete", "Restore", "Cancel job". */
  confirmLabel: string;
  /**
   * Defaults to "Cancel". When the action being confirmed is itself a
   * cancellation, pass something that cannot be misread, e.g. "Keep running".
   */
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
  /**
   * Themed replacement for window.confirm — resolves true if confirmed. The
   * title and button label are required so every confirmation says what it
   * is about to do, and to what.
   */
  confirm: (opts: ConfirmOptions) => Promise<boolean>;
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
