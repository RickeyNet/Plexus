import { useDeferredValue, useMemo } from 'react';

import { useAuthStatus } from '@/api/auth';
import { useInventoryGroupsFull } from '@/api/inventory';
import { canWriteFeature } from '@/lib/tabGating';

/** Hooks the Routing page's tabs, its dialogs and the device page share. */

/** Whether the caller may change routing objects (admin or `routing.write`). */
export function useCanWriteRouting(): boolean {
  return canWriteFeature('routing', useAuthStatus().data);
}

/** Whether the caller may read routing objects (admin or `routing`). */
export function useCanReadRouting(): boolean {
  const auth = useAuthStatus().data;
  return auth?.role === 'admin' || (auth?.feature_access ?? []).includes('routing');
}

export function useDeferredSearch(value: string): string {
  return useDeferredValue(value.trim());
}

/** Every device, by name, from the inventory groups. */
export function useHostOptions(enabled = true) {
  const q = useInventoryGroupsFull(true);
  const options = useMemo(() => {
    const seen = new Map<number, string>();
    for (const g of q.data ?? []) for (const h of g.hosts ?? []) seen.set(h.id, h.hostname || h.ip_address);
    return [...seen.entries()].map(([id, name]) => ({ id, name })).sort((a, b) => a.name.localeCompare(b.name));
  }, [q.data]);
  return { options: enabled ? options : [], query: q };
}
