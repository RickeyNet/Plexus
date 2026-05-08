import { JOB_PRIORITY_LABELS, JOB_PRIORITY_COLORS, type Job } from '@/api/jobs';

export function formatTimestamp(s?: string | null): string {
  if (!s) return '-';
  try {
    const d = new Date(s);
    return d.toLocaleString();
  } catch {
    return s;
  }
}

export function formatTime(s?: string | null): string {
  if (!s) return '';
  try {
    const d = new Date(s);
    return d.toLocaleTimeString();
  } catch {
    return s;
  }
}

export function priorityLabel(p?: number): string {
  if (p == null) return 'Normal';
  return JOB_PRIORITY_LABELS[p] ?? 'Normal';
}

export function priorityColor(p?: number): string {
  if (p == null) return 'text-muted';
  return JOB_PRIORITY_COLORS[p] ?? 'text-muted';
}

export function parseDeps(raw?: string | null): number[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function jobSortKey(j: Job): string {
  return j.started_at || j.queued_at || '';
}

export function parseTags(tags: unknown): string[] {
  if (Array.isArray(tags)) return tags as string[];
  if (typeof tags === 'string') {
    try {
      const parsed = JSON.parse(tags);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }
  return [];
}

export function withinDateRange(dateStr: string, range: 'all' | 'today' | '7d' | '30d'): boolean {
  if (range === 'all') return true;
  const d = new Date(dateStr);
  const diffDays = (Date.now() - d.getTime()) / (1000 * 60 * 60 * 24);
  if (range === 'today') return diffDays < 1;
  if (range === '7d') return diffDays <= 7;
  if (range === '30d') return diffDays <= 30;
  return true;
}
