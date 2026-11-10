import type { ConfigDriftEvent } from '@/api/configuration';

export type BackupView = 'config' | 'diff';

// Only successful captures have a config to diff. An unknown status (detail
// still loading) leaves the diff view available.
export function backupDiffAvailable(status: string | null | undefined): boolean {
  return status == null || status === 'success';
}

export function formatInterval(seconds: number | null | undefined): string {
  if (!seconds) return '-';
  if (seconds % 86400 === 0) return `${seconds / 86400}d`;
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}

export function statusColor(status: string | null | undefined): string {
  if (status === 'open') return 'var(--danger)';
  if (status === 'accepted') return 'var(--warning)';
  return 'var(--success)';
}

// Key a drift on only its changed lines so events with the same logical
// change group together regardless of host-specific surrounding config.
// A unified diff carries 3 lines of context around each hunk; that context
// contains per-host text (interface names, IPs, hostnames), so keying on the
// full diff splits identical changes apart. Keep only the added/removed lines
// (excluding the `---`/`+++` file headers, which also start with -/+).
export function normalizeDiffForGrouping(diffText: string | null | undefined): string {
  if (!diffText) return '';
  return diffText
    .split('\n')
    .filter(
      (line) =>
        (line.startsWith('+') || line.startsWith('-')) &&
        !line.startsWith('---') &&
        !line.startsWith('+++'),
    )
    .join('\n')
    .trim();
}

export interface DriftGroup {
  diff_text: string | null | undefined;
  diff_lines_added?: number;
  diff_lines_removed?: number;
  events: ConfigDriftEvent[];
  representative_id: number;
}

export function groupDriftEvents(events: ConfigDriftEvent[]): DriftGroup[] {
  const groups = new Map<string, DriftGroup>();
  for (const ev of events) {
    const key = normalizeDiffForGrouping(ev.diff_text);
    if (!groups.has(key)) {
      groups.set(key, {
        diff_text: ev.diff_text,
        diff_lines_added: ev.diff_lines_added,
        diff_lines_removed: ev.diff_lines_removed,
        events: [],
        representative_id: ev.id,
      });
    }
    groups.get(key)!.events.push(ev);
  }
  return [...groups.values()].sort((a, b) => b.events.length - a.events.length);
}

export function filterDriftEvents(
  events: ConfigDriftEvent[],
  query: string,
): ConfigDriftEvent[] {
  const q = query.trim().toLowerCase();
  if (!q) return events;
  return events.filter(
    (e) =>
      (e.hostname || '').toLowerCase().includes(q) ||
      (e.ip_address || '').toLowerCase().includes(q) ||
      (e.device_type || '').toLowerCase().includes(q),
  );
}
