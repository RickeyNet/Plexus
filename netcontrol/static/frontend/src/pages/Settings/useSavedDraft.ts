import { useState } from 'react';

import { isDirty } from './unsaved-context';

export interface SavedDraft<T> {
  /** The editable copy; null until the server value first arrives. */
  draft: T | null;
  setDraft: (next: T) => void;
  /** True while the draft differs from the value it was seeded from. */
  dirty: boolean;
  /** Throw the edits away and show the latest server value. */
  discard: () => void;
  /** Adopt the value a successful save returned as the new baseline. */
  markSaved: (saved: T) => void;
}

/**
 * Editable copy of a server value for a Settings form that saves on demand.
 * A refetch (another tab's mutation, window focus, another admin) re-seeds
 * the draft only while it is clean, so it never wipes unsaved edits.
 */
export function useSavedDraft<T>(server: T | undefined): SavedDraft<T> {
  const [baseline, setBaseline] = useState<T | null>(server ?? null);
  const [draft, setDraftState] = useState<T | null>(server ?? null);
  const [prevServer, setPrevServer] = useState(server);

  const dirty = draft !== null && baseline !== null && isDirty(draft, baseline);

  if (server !== prevServer) {
    setPrevServer(server);
    if (server !== undefined && !dirty) {
      setBaseline(server);
      setDraftState(server);
    }
  }

  const reset = (value: T) => {
    setBaseline(value);
    setDraftState(value);
  };

  return {
    draft,
    setDraft: setDraftState,
    dirty,
    discard: () => {
      const latest = server ?? baseline;
      if (latest !== null) reset(latest);
    },
    markSaved: reset,
  };
}
