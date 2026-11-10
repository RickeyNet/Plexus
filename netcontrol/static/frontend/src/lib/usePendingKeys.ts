import { useCallback, useRef, useState } from 'react';

export interface PendingKeys<K> {
  /** True while a task started with this key has not settled. */
  isPending: (key: K) => boolean;
  /** True while any task is in flight. */
  anyPending: boolean;
  /**
   * Runs `task` unless one with the same key is already in flight, in which
   * case the call is ignored. Resolves when the task settles; a rejection
   * from the task propagates, so handle errors inside it.
   */
  run: (key: K, task: () => Promise<unknown>) => Promise<void>;
}

/**
 * Per-row busy state for async row actions. One `useMutation` shared by a
 * list has a single `isPending`, which either disables every row or none;
 * key each action by row id instead and call `mutateAsync` inside `run`
 * (per-call `mutate` callbacks only fire for the latest call, so they
 * cannot release an earlier row).
 *
 *   const pending = usePendingKeys<number>();
 *   const retry = (id: number) =>
 *     pending.run(id, async () => {
 *       try { await retryMut.mutateAsync(id); }
 *       catch (e) { void alert({ message: (e as Error).message, variant: 'error' }); }
 *     });
 *   <BusyButton busy={pending.isPending(row.id)} onClick={() => void retry(row.id)}>
 */
export function usePendingKeys<K extends string | number>(): PendingKeys<K> {
  const [keys, setKeys] = useState<ReadonlySet<K>>(() => new Set());
  // The ref is the guard: two clicks in one frame both see the same state.
  const inFlight = useRef(new Set<K>());

  const run = useCallback(async (key: K, task: () => Promise<unknown>) => {
    if (inFlight.current.has(key)) return;
    inFlight.current.add(key);
    setKeys(new Set(inFlight.current));
    try {
      await task();
    } finally {
      inFlight.current.delete(key);
      setKeys(new Set(inFlight.current));
    }
  }, []);

  const isPending = useCallback((key: K) => keys.has(key), [keys]);

  return { isPending, anyPending: keys.size > 0, run };
}
