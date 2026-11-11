import { MerakiScanJob, useMerakiScanJob } from '@/api/compliance';

import { ScanBanner } from './ScanBanner';

/**
 * Live view of one Meraki compliance scan job: the collection phase while it
 * runs, the outcome once it settles. The parent owns the job id and clears it
 * on dismiss; polling stops by itself when the job reaches a terminal status.
 */
export function MerakiScanProgress({
  jobId,
  onDismiss,
  onShowResults,
}: {
  jobId: string;
  onDismiss: () => void;
  onShowResults?: (scanId: string) => void;
}) {
  const job = useMerakiScanJob(jobId);

  if (job.isError) {
    return (
      <ScanBanner tone="danger" onDismiss={onDismiss}>
        The scan job is no longer available (it may have expired). Check Scan Results for its
        outcome.
      </ScanBanner>
    );
  }
  const data = job.data;
  if (!data || data.status === 'running') {
    return (
      <ScanBanner tone="info">
        <span className="backup-spinner" style={{ marginRight: '0.5rem' }} />
        Scanning {String(data?.progress?.org_name ?? 'organization')}…{' '}
        <span style={{ color: 'var(--text-muted)' }}>{describeProgress(data)}</span>
      </ScanBanner>
    );
  }
  if (data.status === 'failed') {
    return (
      <ScanBanner tone="danger" onDismiss={onDismiss}>
        Scan failed: {data.error || 'unknown error'}
      </ScanBanner>
    );
  }
  const r = data.result;
  const tone = r && r.non_compliant > 0 ? 'warning' : r && r.errors > 0 ? 'danger' : 'success';
  return (
    <ScanBanner tone={tone} onDismiss={onDismiss}>
      <strong>{r?.org_name}</strong> · {r?.profile_name}: {r?.targets} target(s) checked,{' '}
      {r?.non_compliant} non-compliant, {r?.errors} unreadable
      {r && r.collection_warnings > 0 ? `, ${r.collection_warnings} collection warning(s)` : ''}.
      {r && onShowResults && (
        <button
          type="button"
          className="btn btn-sm btn-secondary"
          style={{ marginLeft: '0.75rem' }}
          onClick={() => onShowResults(r.scan_id)}
        >
          Show results
        </button>
      )}
    </ScanBanner>
  );
}

function describeProgress(job: MerakiScanJob | undefined): string {
  const p = job?.progress || {};
  const phase = String(p.phase ?? 'starting');
  const done = typeof p.calls_done === 'number' ? p.calls_done : null;
  const total = typeof p.calls_total === 'number' ? p.calls_total : null;
  if (done != null && total != null && total > 0) return `${phase} (${done}/${total} API calls)`;
  return phase;
}
