import { useMemo } from 'react';

import { type DcimKind, useDcimChoices, useDcimList } from '@/api/dcim';
import { useGeoSites } from '@/api/floorPlan';
import { useInventoryGroupsFull } from '@/api/inventory';
import { useAuthStatus } from '@/api/auth';
import { canWriteFeature } from '@/lib/tabGating';

export interface Option {
  value: number;
  label: string;
}

/** Every inventory host as a picker option, by name. */
export function useHostOptions(): Option[] {
  const groups = useInventoryGroupsFull(true);
  return useMemo(() => {
    const seen = new Map<number, string>();
    for (const g of groups.data ?? []) {
      for (const h of g.hosts ?? []) seen.set(h.id, h.hostname || h.ip_address);
    }
    return [...seen.entries()].map(([value, label]) => ({ value, label })).sort((a, b) => a.label.localeCompare(b.label));
  }, [groups.data]);
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
