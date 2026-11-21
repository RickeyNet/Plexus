/**
 * Software end of life per release series - the status of the series a
 * tracked device runs (carried by the software overview), and the
 * administrator's end-of-life entries (`/api/software/eol-entries`).
 * Not the hardware lifecycle (`./lifecycle`).
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

export type SoftwareEolState = 'supported' | 'ending' | 'end_of_life' | 'unknown';

/** The end-of-life status of the series one device runs. */
export interface SoftwareEolStatus {
  /** `25.1`, `17.9`; '' when no entry or built-in rule names one. */
  series: string;
  status: SoftwareEolState;
  /** The end of life (`YYYY-MM-DD`): the day security fixes stop. */
  date: string | null;
  /** Days to that date; negative once passed. */
  days: number | null;
  /** `entry` (administrator), `estimate` (OPNsense release cadence), `reported` (the device reports a newer major release). */
  source: 'entry' | 'estimate' | 'reported' | '';
  estimate: boolean;
  /** One line saying how the status is known. */
  basis: string;
  successor: string;
  url: string;
  release_date: string;
}

export interface SoftwareEolEntry {
  id: number;
  platform: string;
  series: string;
  eol_date: string;
  release_date: string;
  url: string;
  notes: string;
  source: 'manual' | 'import' | string;
  enabled: boolean;
  created_at: string;
  created_by: string;
  updated_at: string;
  updated_by: string;
}

export interface SoftwareEolEntryPayload {
  platform: string;
  series: string;
  eol_date: string;
  release_date?: string;
  url?: string;
  notes?: string;
  enabled?: boolean;
}

const ENTRIES_KEY = ['software-eol-entries'] as const;

function invalidate(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: ENTRIES_KEY });
  // The statuses and the generated advisories and alerts change with the entries.
  qc.invalidateQueries({ queryKey: ['software-overview'] });
}

export function useSoftwareEolEntries() {
  return useQuery<{ entries: SoftwareEolEntry[]; warn_days: number }>({
    queryKey: ENTRIES_KEY,
    queryFn: () => apiRequest('/software/eol-entries'),
  });
}

export function useSaveSoftwareEolEntry() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, payload }: { id: number | null; payload: SoftwareEolEntryPayload }) =>
      id == null
        ? apiRequest<{ entry: SoftwareEolEntry }>('/software/eol-entries', { method: 'POST', body: payload })
        : apiRequest<{ entry: SoftwareEolEntry }>(`/software/eol-entries/${id}`, { method: 'PUT', body: payload }),
    onSuccess: () => invalidate(qc),
  });
}

export function useDeleteSoftwareEolEntry() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => apiRequest(`/software/eol-entries/${id}`, { method: 'DELETE' }),
    onSuccess: () => invalidate(qc),
  });
}
