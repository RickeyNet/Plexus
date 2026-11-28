import { useDeferredValue } from 'react';

import { useAuthStatus } from '@/api/auth';
import { type HostOption, useHostOptions as useInventoryHostOptions } from '@/api/inventory';
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

const NO_HOSTS: HostOption[] = [];

/** Every device, by name, from the inventory groups (api/inventory's shared host options). */
export function useHostOptions(enabled = true) {
  const query = useInventoryHostOptions(enabled);
  return { options: enabled ? (query.data ?? NO_HOSTS) : NO_HOSTS, query };
}
