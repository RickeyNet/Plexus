import type { InventoryGroupFull } from '@/api/inventory';
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

/** Statuses of a job that has not finished: awaiting approval, queued or running. */
const UNFINISHED_JOB_STATUSES = new Set(['pending_approval', 'queued', 'running']);
/** Statuses a job can be retried from (a denied one asks for approval again). */
const RETRYABLE_JOB_STATUSES = new Set(['failed', 'cancelled', 'denied']);

/** Whether a job can still be cancelled (it has not finished). */
export function isJobCancellable(status?: string | null): boolean {
  return UNFINISHED_JOB_STATUSES.has(status ?? '');
}

/** Whether a job has finished (success, failure, cancelled or denied). */
export function isJobFinished(status?: string | null): boolean {
  return Boolean(status) && !UNFINISHED_JOB_STATUSES.has(status ?? '');
}

export function isJobRetryable(status?: string | null): boolean {
  return RETRYABLE_JOB_STATUSES.has(status ?? '');
}

/** What a job targets, for its list row: its dynamic group, else its inventory group. */
export function jobTargetLabel(job: Pick<Job, 'dynamic_group_name' | 'group_name'>): string {
  return job.dynamic_group_name ? `Dynamic group: ${job.dynamic_group_name}` : `Group: ${job.group_name || 'Unknown'}`;
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

/**
 * The launch picker's groups narrowed to a search. A group whose name or path
 * matches keeps all its hosts; otherwise it keeps the hosts matching on
 * hostname, address or device type, and drops out when none do.
 */
export function filterTargetGroups(groups: InventoryGroupFull[], query: string): InventoryGroupFull[] {
  const q = query.trim().toLowerCase();
  if (!q) return groups;
  const out: InventoryGroupFull[] = [];
  for (const g of groups) {
    if (g.name.toLowerCase().includes(q) || (g.path ?? '').toLowerCase().includes(q)) {
      out.push(g);
      continue;
    }
    const hosts = (g.hosts ?? []).filter((h) =>
      h.hostname.toLowerCase().includes(q) ||
      h.ip_address.toLowerCase().includes(q) ||
      (h.device_type ?? '').toLowerCase().includes(q),
    );
    if (hosts.length > 0) out.push({ ...g, hosts });
  }
  return out;
}

/** Distinct hosts across the launch picker's groups. */
export function countTargetHosts(groups: InventoryGroupFull[]): number {
  const ids = new Set<number>();
  for (const g of groups) for (const h of g.hosts ?? []) ids.add(h.id);
  return ids.size;
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
