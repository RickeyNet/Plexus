import { useMemo } from 'react';

import { type DcimKind, useDcimChoices, useDcimList } from '@/api/dcim';
import { useGeoSites } from '@/api/floorPlan';
import { useHostOptions as useInventoryHostOptions } from '@/api/inventory';
import { useAuthStatus } from '@/api/auth';
import { canWriteFeature } from '@/lib/tabGating';

export interface Option {
  value: number;
  label: string;
}

/** Every inventory host as a picker option, by name (api/inventory's shared host options). */
export function useHostOptions(): Option[] {
  const hosts = useInventoryHostOptions();
  return useMemo(() => (hosts.data ?? []).map((h) => ({ value: h.id, label: h.label })), [hosts.data]);
}

export function useSiteOptions(): Option[] {
  const sites = useGeoSites();
  return useMemo(() => (sites.data ?? []).map((s) => ({ value: s.id, label: s.name })), [sites.data]);
}

/** The records of `kind` as picker options (`label` builds each label). */
export function useRecordOptions(kind: DcimKind, label: (r: Record<string, unknown>) => string, enabled = true): Option[] {
  const q = useDcimList(kind, {}, enabled);
  return useMemo(() => (q.data ?? []).map((r) => ({ value: r.id, label: label(r) })), [q.data, label]);
}

/** The DCIM choice sets (empty lists until loaded). */
export function useChoices() {
  const q = useDcimChoices();
  return (key: keyof NonNullable<typeof q.data>): string[] => (q.data?.[key] as string[] | undefined) ?? [];
}

/** Whether the user may change DCIM records (admin, or `dcim.write`). */
export function useCanWriteDcim(): boolean {
  return canWriteFeature('dcim', useAuthStatus().data);
}
