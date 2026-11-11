import { useComplianceScanJob } from '@/api/compliance';
import { ProgressBar } from '@/components/ProgressBar';

import { ScanBanner } from './ScanBanner';
import { hostScanOutcome, scanPercent } from './scanHelpers';

/**
 * Live view of one host compliance scan job (bulk scan or assignment Scan
 * Now): hosts done of total while it runs, the outcome once it settles. The
 * scan runs server-side, so unmounting this does not stop it; polling stops by
 * itself on a terminal status.
 */
export function HostScanProgress({
  jobId,
  onDismiss,
  onShowResults,
}: {
  jobId: string;
  onDismiss: () => void;
  onShowResults?: () => void;
}) {
  const job = useComplianceScanJob(jobId);

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
    const p = data?.progress;
    const total = p?.hosts_total ?? 0;
    const done = p?.hosts_done ?? 0;
    return (
      <ScanBanner tone="info">
        <div>
          <span className="backup-spinner" style={{ marginRight: '0.5rem' }} />
          {total > 0 ? `Scanning ${done} of ${total} hosts…` : 'Starting scan…'}
          {p?.profile_name && <span style={{ color: 'var(--text-muted)' }}> · {p.profile_name}</span>}
        </div>
        <ProgressBar
          value={scanPercent(done, total)}
          label="Compliance scan progress"
          style={{ margin: '0.4rem 0' }}
        />
        <div style={{ fontSize: '0.85em', color: 'var(--text-muted)' }}>
          {p?.violations ?? 0} non-compliant, {p?.errors ?? 0} error(s) so far
        </div>
      </ScanBanner>
    );
  }
  const { tone, message } = hostScanOutcome(data);
  return (
    <ScanBanner tone={tone} onDismiss={onDismiss}>
      {data.progress?.profile_name && <strong>{data.progress.profile_name}: </strong>}
      {message}
      {onShowResults && data.status !== 'failed' && (
        <button
          type="button"
          className="btn btn-sm btn-secondary"
          style={{ marginLeft: '0.75rem' }}
          onClick={onShowResults}
        >
          Show results
        </button>
      )}
    </ScanBanner>
  );
}
