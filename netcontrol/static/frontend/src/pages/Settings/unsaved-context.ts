import { createContext, useContext, useEffect, useId, useMemo, useRef } from 'react';

/**
 * Tracks which Settings forms hold edits that have not been saved, so the
 * page can ask before a tab switch or a reload throws them away.
 */
export interface UnsavedRegistry {
  /** Register (label) or clear (null) the unsaved state of one form. */
  set: (id: string, label: string | null) => void;
  /** Labels of the forms that currently hold unsaved edits. */
  labels: () => string[];
}

export const UnsavedContext = createContext<UnsavedRegistry | null>(null);

/** Order-sensitive structural comparison of a draft against its saved value. */
export function isDirty<T>(draft: T, saved: T): boolean {
  return JSON.stringify(draft) !== JSON.stringify(saved);
}

/**
 * Creates the registry the Settings page provides to its tabs, and warns on
 * reload or window close while any form is dirty.
 */
export function useUnsavedRegistry(): UnsavedRegistry {
  const forms = useRef(new Map<string, string>());
  const registry = useMemo<UnsavedRegistry>(
    () => ({
      set: (id, label) => {
        if (label === null) forms.current.delete(id);
        else forms.current.set(id, label);
      },
      labels: () => Array.from(forms.current.values()),
    }),
    [],
  );

  useEffect(() => {
    const onBeforeUnload = (e: BeforeUnloadEvent) => {
      if (forms.current.size > 0) e.preventDefault();
    };
    window.addEventListener('beforeunload', onBeforeUnload);
    return () => window.removeEventListener('beforeunload', onBeforeUnload);
  }, []);

  return registry;
}

/**
 * Report a form's unsaved state. `label` names the form in the confirmation
 * ("Login Rules"). Clears itself on unmount. A no-op outside the Settings page.
 */
export function useReportUnsaved(label: string, dirty: boolean): void {
  const registry = useContext(UnsavedContext);
  const id = useId();
  useEffect(() => {
    if (!registry) return;
    registry.set(id, dirty ? label : null);
    return () => registry.set(id, null);
  }, [registry, id, label, dirty]);
}
