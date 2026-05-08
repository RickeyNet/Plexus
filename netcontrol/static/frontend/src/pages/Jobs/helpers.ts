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

function parseStampMs(s: string | null | undefined): number {
  if (!s) return 0;
  const normalized = /Z$|[+-]\d{2}:?\d{2}$/.test(s) ? s : `${s}Z`;
  const t = Date.parse(normalized);
  return Number.isFinite(t) ? t : 0;
}

export function jobSortKey(j: Job): string {
  // Kept for compatibility; new code should use jobSortValue.
  return j.started_at || j.queued_at || '';
}

export function compareJobsDesc(a: Job, b: Job): number {
  const av = parseStampMs(a.started_at || a.queued_at);
  const bv = parseStampMs(b.started_at || b.queued_at);
  if (bv !== av) return bv - av;
  return (b.id ?? 0) - (a.id ?? 0);
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
  const ms = parseStampMs(dateStr);
  if (!ms) return false;
  const diffDays = (Date.now() - ms) / (1000 * 60 * 60 * 24);
  if (range === 'today') return diffDays < 1;
  if (range === '7d') return diffDays <= 7;
  if (range === '30d') return diffDays <= 30;
  return true;
}
