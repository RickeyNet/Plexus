import { useMemo, useState } from 'react';

import {
  useCancelJob,
  useJobQueue,
  useJobs,
  useRetryJob,
  type Job,
} from '@/api/jobs';

import {
  formatTimestamp,
  jobSortKey,
  parseDeps,
  priorityColor,
  priorityLabel,
  withinDateRange,
} from './helpers';
import { JobOutputModal } from './JobOutputModal';
import { LaunchJobModal } from './LaunchJobModal';

type StatusFilter = 'all' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
type DryRunFilter = 'all' | 'yes' | 'no';
type DateRange = 'all' | 'today' | '7d' | '30d';

export function JobsTab() {
  const jobsQuery = useJobs(100);
  const queueQuery = useJobQueue();
  const cancelMut = useCancelJob();
  const retryMut = useRetryJob();

  const [query, setQuery] = useState('');
  const [status, setStatus] = useState<StatusFilter>('all');
  const [dryRun, setDryRun] = useState<DryRunFilter>('all');
  const [dateRange, setDateRange] = useState<DateRange>('all');

  const [showLaunch, setShowLaunch] = useState(false);
  const [viewJobId, setViewJobId] = useState<number | null>(null);

  const filtered = useMemo(() => {
    const items = jobsQuery.data ?? [];
    const q = query.trim().toLowerCase();
    return items
      .filter((j) => {
        const text = !q ||
          (j.playbook_name ?? '').toLowerCase().includes(q) ||
          (j.group_name ?? '').toLowerCase().includes(q) ||
          (j.status ?? '').toLowerCase().includes(q);
        const matchesStatus = status === 'all' || (j.status ?? '').toLowerCase() === status;
        const isDry = Boolean(j.dry_run);
        const matchesDry = dryRun === 'all' || (dryRun === 'yes' && isDry) || (dryRun === 'no' && !isDry);
        const ds = j.started_at || j.queued_at;
        const matchesDate = !ds || withinDateRange(ds, dateRange);
        return text && matchesStatus && matchesDry && matchesDate;
      })
      .sort((a, b) => jobSortKey(b).localeCompare(jobSortKey(a)));
  }, [jobsQuery.data, query, status, dryRun, dateRange]);

  function handleCancel(id: number) {
    if (!confirm('Cancel this job?')) return;
    cancelMut.mutate(id, { onError: (e) => alert((e as Error).message) });
  }

  function handleRetry(id: number) {
    retryMut.mutate(id, {
      onSuccess: (r) => setViewJobId(r.job_id),
      onError: (e) => alert((e as Error).message),
    });
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '0.75rem' }}>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <input className="form-input" placeholder="Search jobs…" value={query} onChange={(e) => setQuery(e.target.value)} style={{ width: 220 }} />
          <select className="form-select" value={status} onChange={(e) => setStatus(e.target.value as StatusFilter)}>
            <option value="all">All Statuses</option>
            <option value="queued">Queued</option>
            <option value="running">Running</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
            <option value="cancelled">Cancelled</option>
          </select>
          <select className="form-select" value={dryRun} onChange={(e) => setDryRun(e.target.value as DryRunFilter)}>
            <option value="all">Dry+Live</option>
            <option value="yes">Dry Run only</option>
            <option value="no">Live only</option>
          </select>
          <select className="form-select" value={dateRange} onChange={(e) => setDateRange(e.target.value as DateRange)}>
            <option value="all">All time</option>
            <option value="today">Today</option>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
          </select>
        </div>
        <button className="btn btn-primary" onClick={() => setShowLaunch(true)}>+ Launch Job</button>
      </div>

      <QueuePanel data={queueQuery.data} />

      {jobsQuery.isPending && <p className="text-muted">Loading…</p>}
      {jobsQuery.error && <p style={{ color: 'var(--danger)' }}>Failed: {(jobsQuery.error as Error).message}</p>}
      {jobsQuery.data && (filtered.length === 0 ? (
        <div className="empty-state">No matching jobs</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {filtered.map((j) => (
            <JobRow
              key={j.id}
              job={j}
              onView={() => setViewJobId(j.id)}
              onCancel={() => handleCancel(j.id)}
              onRetry={() => handleRetry(j.id)}
            />
          ))}
        </div>
      ))}

      <LaunchJobModal
        isOpen={showLaunch}
        onClose={() => setShowLaunch(false)}
        onLaunched={(jobId) => setViewJobId(jobId)}
      />
      <JobOutputModal
        jobId={viewJobId}
        onClose={() => setViewJobId(null)}
        onRetried={(newId) => setViewJobId(newId)}
      />
    </div>
  );
}

function QueuePanel({ data }: { data: ReturnType<typeof useJobQueue>['data'] }) {
  if (!data) return null;
  if (data.running === 0 && data.queued === 0) return null;
  return (
    <div className="card" style={{ padding: '0.75rem 1rem', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
      <div style={{ fontWeight: 600 }}>
        Queue: <span style={{ color: 'var(--success)' }}>{data.running}</span>/{data.max_concurrent} running
        {data.queued > 0 && <> • <span>{data.queued} queued</span></>}
      </div>
      <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
        {(data.jobs || []).map((j) => {
          const isRunning = j.status === 'running';
          return (
            <span
              key={j.id}
              className={`status-badge`}
              title={`${j.playbook_name ?? ''} — ${priorityLabel(j.priority)}`}
              style={{ background: isRunning ? 'var(--success)' : 'var(--bg-secondary)', color: isRunning ? '#fff' : 'inherit' }}
            >
              {(j.playbook_name ?? 'Job').substring(0, 20)}
              {!isRunning && ` — ${priorityLabel(j.priority)}`}
            </span>
          );
        })}
      </div>
    </div>
  );
}

function JobRow({ job, onView, onCancel, onRetry }: { job: Job; onView: () => void; onCancel: () => void; onRetry: () => void }) {
  const showPri = job.priority != null && job.priority !== 2;
  const deps = parseDeps(job.depends_on);
  const timeLabel = job.started_at ? `Started: ${formatTimestamp(job.started_at)}` :
    job.queued_at ? `Queued: ${formatTimestamp(job.queued_at)}` : '';
  return (
    <div className="card" style={{ padding: '0.75rem 1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem' }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          {job.playbook_name || 'Unknown'}
          {showPri && (
            <span className="badge" style={{ background: `var(--${priorityColor(job.priority)})`, color: '#fff' }}>
              {priorityLabel(job.priority)}
            </span>
          )}
          {deps.length > 0 && <span className="badge badge-secondary" title={`Depends on jobs: ${deps.join(', ')}`}>deps: {deps.join(', ')}</span>}
        </div>
        <div className="text-muted" style={{ fontSize: '0.85rem', marginTop: '0.25rem' }}>
          Group: {job.group_name || 'Unknown'} • {timeLabel} •{' '}
          <span className={`status-badge status-${job.status}`}>{job.status}</span>
          {job.dry_run && <> • <span style={{ color: 'var(--warning)' }}>DRY RUN</span></>}
          {job.launched_by && <> • by {job.launched_by}</>}
        </div>
      </div>
      <div style={{ display: 'flex', gap: '0.4rem' }}>
        {(job.status === 'running' || job.status === 'queued') && (
          <button className="btn btn-sm btn-danger" onClick={(e) => { e.stopPropagation(); onCancel(); }}>Cancel</button>
        )}
        {(job.status === 'failed' || job.status === 'cancelled') && (
          <button className="btn btn-sm btn-primary" onClick={(e) => { e.stopPropagation(); onRetry(); }}>Retry</button>
        )}
        <button className="btn btn-sm btn-secondary" onClick={onView}>View Output</button>
      </div>
    </div>
  );
}
