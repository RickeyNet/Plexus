import type { ComplianceScanJob } from '@/api/compliance';
import type { CalloutTone } from '@/components/Callout';
import type { Tone } from '@/lib/severity';

/** Height cap of the scan result / status tables; their header row stays in view while they scroll. */
export const RESULTS_TABLE_MAX_HEIGHT = 600;

/** Percent of hosts done, or null while the total is not known yet. */
export function scanPercent(done: number | null | undefined, total: number | null | undefined): number | null {
  if (!total || total <= 0) return null;
  return Math.round(((done ?? 0) / total) * 100);
}

/** Outcome line of a settled host scan job, and the banner tone for it. */
export function hostScanOutcome(job: Pick<ComplianceScanJob, 'status' | 'result' | 'error'>): {
  tone: CalloutTone;
  message: string;
} {
  if (job.status === 'failed') {
    return { tone: 'danger', message: `Scan failed: ${job.error || 'unknown error'}` };
  }
  const r = job.result;
  const note = job.status === 'partial' && job.error ? ` ${job.error}` : '';
  if (!r) return { tone: job.status === 'partial' ? 'warning' : 'success', message: `Scan finished.${note}` };
  if (r.hosts_scanned === 0) return { tone: 'warning', message: `No hosts were scanned.${note}` };
  if (r.violations > 0) {
    return {
      tone: 'warning',
      message: `${r.hosts_scanned} host(s) scanned, ${r.violations} non-compliant, ${r.errors} error(s).${note}`,
    };
  }
  if (r.errors > 0) {
    return { tone: 'danger', message: `${r.hosts_scanned} host(s) scanned, ${r.errors} error(s).${note}` };
  }
  return {
    tone: job.status === 'partial' ? 'warning' : 'success',
    message: `${r.hosts_scanned} host(s) scanned - all compliant.${note}`,
  };
}

/** PASS / FAIL / UNREADABLE of one finding and its tone. */
export function findingOutcome(f: { passed: boolean | null; unreadable?: boolean }): {
  label: 'PASS' | 'FAIL' | 'UNREADABLE';
  tone: Tone;
} {
  if (f.unreadable) return { label: 'UNREADABLE', tone: 'warning' };
  return f.passed ? { label: 'PASS', tone: 'success' } : { label: 'FAIL', tone: 'danger' };
}
