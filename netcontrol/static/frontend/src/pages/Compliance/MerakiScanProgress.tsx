import type { ReactNode } from 'react';

import { MerakiScanJob, useMerakiScanJob } from '@/api/compliance';

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
      <Banner tone="danger" onDismiss={onDismiss}>
        The scan job is no longer available (it may have expired). Check Scan Results for its
        outcome.
      </Banner>
    );
  }
  const data = job.data;
  if (!data || data.status === 'running') {
    return (
      <Banner tone="info">
        <span className="spinner" style={{ marginRight: '0.5rem' }} />
        Scanning {String(data?.progress?.org_name ?? 'organization')}…{' '}
        <span style={{ color: 'var(--text-muted)' }}>{describeProgress(data)}</span>
      </Banner>
    );
  }
  if (data.status === 'failed') {
    return (
      <Banner tone="danger" onDismiss={onDismiss}>
        Scan failed: {data.error || 'unknown error'}
      </Banner>
    );
  }
  const r = data.result;
  const tone = r && r.non_compliant > 0 ? 'warning' : r && r.errors > 0 ? 'danger' : 'success';
  return (
    <Banner tone={tone} onDismiss={onDismiss}>
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
    </Banner>
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

function Banner({
  tone,
  children,
  onDismiss,
}: {
  tone: 'info' | 'success' | 'warning' | 'danger';
  children: ReactNode;
  onDismiss?: () => void;
}) {
  const color = tone === 'info' ? 'var(--primary)' : `var(--${tone})`;
  return (
    <div
      className="card"
      style={{
        marginBottom: '0.75rem',
        padding: '0.6rem 0.9rem',
        borderLeft: `4px solid ${color}`,
        display: 'flex',
        alignItems: 'center',
        gap: '0.5rem',
        flexWrap: 'wrap',
        fontSize: '0.9em',
      }}
    >
      <div style={{ flex: 1 }}>{children}</div>
      {onDismiss && (
        <button type="button" className="btn btn-sm btn-ghost" onClick={onDismiss}>
          Dismiss
        </button>
      )}
    </div>
  );
}
