import { type ReactNode, useCallback, useMemo, useRef, useState } from 'react';

import { AlertDialog } from './AlertDialog';
import { ConfirmDialog } from './ConfirmDialog';
import {
  type AlertOptions,
  type ConfirmOptions,
  DialogContext,
  type DialogApi,
} from './DialogProvider-context';

type Pending =
  | { kind: 'confirm'; opts: ConfirmOptions; resolve: (v: boolean) => void }
  | { kind: 'alert'; opts: AlertOptions; resolve: () => void };

/**
 * App-wide themed alternatives to the browser's native confirm()/alert(),
 * exposed as promises so imperative handlers can `await confirm(...)` with
 * almost no restructuring. Native dialogs are serial, so a second request that
 * arrives while one is open is queued rather than dropped.
 *
 * All queue bookkeeping lives in refs and event handlers (never inside a state
 * updater) so it stays correct under StrictMode's double-invoked updaters.
 */
export function DialogProvider({ children }: { children: ReactNode }) {
  const [active, setActive] = useState<Pending | null>(null);
  const activeRef = useRef<Pending | null>(null);
  const queueRef = useRef<Pending[]>([]);

  const enqueue = useCallback((item: Pending) => {
    if (activeRef.current) {
      queueRef.current.push(item);
    } else {
      activeRef.current = item;
      setActive(item);
    }
  }, []);

  const advance = useCallback(() => {
    const next = queueRef.current.shift() ?? null;
    activeRef.current = next;
    setActive(next);
  }, []);

  const confirm = useCallback(
    (o: ConfirmOptions | string) =>
      new Promise<boolean>((resolve) => {
        const opts = typeof o === 'string' ? { message: o } : o;
        enqueue({ kind: 'confirm', opts, resolve });
      }),
    [enqueue],
  );

  const alert = useCallback(
    (o: AlertOptions | string) =>
      new Promise<void>((resolve) => {
        const opts = typeof o === 'string' ? { message: o } : o;
        enqueue({ kind: 'alert', opts, resolve });
      }),
    [enqueue],
  );

  const api = useMemo<DialogApi>(() => ({ confirm, alert }), [confirm, alert]);

  return (
    <DialogContext.Provider value={api}>
      {children}
      {active?.kind === 'confirm' && (
        <ConfirmDialog
          isOpen
          title={active.opts.title ?? 'Please confirm'}
          message={active.opts.message}
          confirmLabel={active.opts.confirmLabel}
          cancelLabel={active.opts.cancelLabel}
          confirmVariant={active.opts.confirmVariant ?? 'danger'}
          onConfirm={() => {
            const { resolve } = active;
            advance();
            resolve(true);
          }}
          onCancel={() => {
            const { resolve } = active;
            advance();
            resolve(false);
          }}
        />
      )}
      {active?.kind === 'alert' && (
        <AlertDialog
          isOpen
          title={active.opts.title ?? 'Notice'}
          message={active.opts.message}
          okLabel={active.opts.okLabel}
          variant={active.opts.variant}
          onClose={() => {
            const { resolve } = active;
            advance();
            resolve();
          }}
        />
      )}
    </DialogContext.Provider>
  );
}
