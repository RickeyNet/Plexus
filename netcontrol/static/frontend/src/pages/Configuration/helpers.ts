import type { ConfigDriftEvent } from '@/api/configuration';

export function formatStamp(iso: string | null | undefined): string {
  if (!iso) return '';
  const hasZone = iso.includes('Z') || iso.includes('+');
  return new Date(iso + (hasZone ? '' : 'Z')).toLocaleString();
}

export function formatRelative(iso: string | null | undefined): string {
  if (!iso) return 'Never';
  const hasZone = iso.includes('Z') || iso.includes('+');
  const dt = new Date(iso + (hasZone ? '' : 'Z'));
  const diffMs = Date.now() - dt.getTime();
  const sec = Math.floor(diffMs / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const days = Math.floor(hr / 24);
  return `${days}d ago`;
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

// Strip diff headers/hunk lines so events with the same logical change
// group together regardless of host-specific paths/positions.
export function normalizeDiffForGrouping(diffText: string | null | undefined): string {
  if (!diffText) return '';
  return diffText
    .split('\n')
    .filter(
      (line) =>
        !line.startsWith('---') &&
        !line.startsWith('+++') &&
        !line.startsWith('@@'),
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
