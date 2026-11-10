import { JOB_PRIORITY_LABELS, JOB_PRIORITY_TONES, type Job } from '@/api/jobs';
import { toDate } from '@/lib/datetime';
import { type Tone } from '@/lib/severity';

export function priorityLabel(p?: number): string {
  if (p == null) return 'Normal';
  return JOB_PRIORITY_LABELS[p] ?? 'Normal';
}

export function priorityTone(p?: number): Tone {
  if (p == null) return 'neutral';
  return JOB_PRIORITY_TONES[p] ?? 'neutral';
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

function stampMs(s: string | null | undefined): number {
  return toDate(s)?.getTime() ?? 0;
}

export function jobSortKey(j: Job): string {
  // Kept for compatibility; new code should use jobSortValue.
  return j.started_at || j.queued_at || '';
}

export function compareJobsDesc(a: Job, b: Job): number {
  const av = stampMs(a.started_at || a.queued_at);
  const bv = stampMs(b.started_at || b.queued_at);
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
  const ms = stampMs(dateStr);
  if (!ms) return false;
  const diffDays = (Date.now() - ms) / (1000 * 60 * 60 * 24);
  if (range === 'today') return diffDays < 1;
  if (range === '7d') return diffDays <= 7;
  if (range === '30d') return diffDays <= 30;
  return true;
}
