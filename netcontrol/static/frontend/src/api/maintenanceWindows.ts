import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

// ── Types ──────────────────────────────────────────────────────────────────

export type WindowRecurrence = 'none' | 'daily' | 'weekly';
export type WindowPolicy =
  | 'allow_changes'
  | 'block_outside_window'
  | 'warn_outside_window';

export interface MaintenanceWindowScope {
  group_id: number;
  group_name?: string | null;
}

export interface MaintenanceWindow {
  id: number;
  name: string;
  description: string;
  start_at: string;
  end_at: string;
  recurrence: WindowRecurrence;
  weekday_mask: number;
  policy: WindowPolicy;
  enabled: number;
  created_by?: string | null;
  created_at?: string | null;
  group_ids: number[];
  scopes: MaintenanceWindowScope[];
  is_active?: boolean;
}

export interface MaintenanceWindowPayload {
  name: string;
  description?: string;
  start_at: string;
  end_at: string;
  recurrence: WindowRecurrence;
  weekday_mask: number;
  policy: WindowPolicy;
  enabled: boolean;
  group_ids: number[];
}

export interface GateVerdict {
  allowed: boolean;
  reason: string;
  policy: string;
  warning: string;
  window: MaintenanceWindow | null;
}

// ── Queries ────────────────────────────────────────────────────────────────

export function useMaintenanceWindows() {
  return useQuery<MaintenanceWindow[]>({
    queryKey: ['maintenance-windows'],
    queryFn: () => apiRequest('/maintenance-windows'),
  });
}

export function useMaintenanceWindow(id: number | null) {
  return useQuery<MaintenanceWindow>({
    queryKey: ['maintenance-window', id],
    queryFn: () => apiRequest(`/maintenance-windows/${id}`),
    enabled: id != null,
  });
}

// ── Mutations ──────────────────────────────────────────────────────────────

function invalidate(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: ['maintenance-windows'] });
}

export function useCreateMaintenanceWindow() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: MaintenanceWindowPayload) =>
      apiRequest<{ id: number }>('/maintenance-windows', {
        method: 'POST',
        body: data,
      }),
    onSuccess: () => invalidate(qc),
  });
}

export function useUpdateMaintenanceWindow() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: Partial<MaintenanceWindowPayload> }) =>
      apiRequest(`/maintenance-windows/${id}`, {
        method: 'PUT',
        body: data,
      }),
    onSuccess: () => invalidate(qc),
  });
}

export function useDeleteMaintenanceWindow() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/maintenance-windows/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidate(qc),
  });
}

// ── Weekday mask helpers ────────────────────────────────────────────────────

export const WEEKDAYS: Array<{ bit: number; short: string; label: string }> = [
  { bit: 1 << 0, short: 'Mon', label: 'Monday' },
  { bit: 1 << 1, short: 'Tue', label: 'Tuesday' },
  { bit: 1 << 2, short: 'Wed', label: 'Wednesday' },
  { bit: 1 << 3, short: 'Thu', label: 'Thursday' },
  { bit: 1 << 4, short: 'Fri', label: 'Friday' },
  { bit: 1 << 5, short: 'Sat', label: 'Saturday' },
  { bit: 1 << 6, short: 'Sun', label: 'Sunday' },
];

export function formatWeekdayMask(mask: number): string {
  return WEEKDAYS.filter((d) => mask & d.bit)
    .map((d) => d.short)
    .join(', ');
}

export function toggleWeekdayBit(mask: number, bit: number): number {
  return mask & bit ? mask & ~bit : mask | bit;
}
