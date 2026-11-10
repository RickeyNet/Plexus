import { useMemo, useState } from 'react';

import { Badge, StatusBadge } from '@/components/Badge';
import { Callout } from '@/components/Callout';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  useCancelJob,
  useJobQueue,
  useJobs,
  useRetryJob,
  type Job,
} from '@/api/jobs';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { formatBackendDateTime } from '@/lib/datetime';

import {
  compareJobsDesc,
  parseDeps,
  priorityLabel,
  priorityTone,
  withinDateRange,
} from './helpers';
import { JobOutputModal } from './JobOutputModal';
import { LaunchJobModal } from './LaunchJobModal';

type StatusFilter = 'all' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
type DryRunFilter = 'all' | 'yes' | 'no';
type DateRange = 'all' | 'today' | '7d' | '30d';

export function JobsTab() {
  const { confirm, alert } = useDialogs();
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
      .sort(compareJobsDesc);
  }, [jobsQuery.data, query, status, dryRun, dateRange]);

  async function handleCancel(id: number) {
    const ok = await confirm({
      title: 'Cancel job',
      message: `Cancel job #${id}?`,
      confirmLabel: 'Cancel job',
      cancelLabel: 'Keep running',
    });
    if (!ok) return;
    cancelMut.mutate(id, { onError: (e) => { void alert({ message: (e as Error).message, variant: 'error' }); } });
  }

  function handleRetry(id: number) {
    retryMut.mutate(id, {
      onSuccess: (r) => setViewJobId(r.job_id),
      onError: (e) => { void alert({ message: (e as Error).message, variant: 'error' }); },
    });
  }

  return (
    <div className="stack">
      <div className="toolbar">
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
        <span className="toolbar-spacer" />
        <button className="btn btn-primary" onClick={() => setShowLaunch(true)}>+ Launch Job</button>
      </div>

      <QueuePanel data={queueQuery.data} />

      {jobsQuery.isPending && <LoadingState />}
      {jobsQuery.error && <Callout tone="danger">Failed: {(jobsQuery.error as Error).message}</Callout>}
      {jobsQuery.data && (filtered.length === 0 ? (
        <EmptyState message="No matching jobs" />
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
    <div className="card card-sm" style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)', flexWrap: 'wrap' }}>
      <div style={{ fontWeight: 600 }}>
        Queue: <span style={{ color: 'var(--success)' }}>{data.running}</span>/{data.max_concurrent} running
        {data.queued > 0 && <> • <span>{data.queued} queued</span></>}
      </div>
      <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
        {(data.jobs || []).map((j) => {
          const isRunning = j.status === 'running';
          return (
            <Badge
              key={j.id}
              tone={isRunning ? 'info' : 'neutral'}
              live={isRunning}
              title={`${j.playbook_name ?? ''} - ${priorityLabel(j.priority)}`}
            >
              {(j.playbook_name ?? 'Job').substring(0, 20)}
              {!isRunning && ` - ${priorityLabel(j.priority)}`}
            </Badge>
          );
        })}
      </div>
    </div>
  );
}

function JobRow({ job, onView, onCancel, onRetry }: { job: Job; onView: () => void; onCancel: () => void; onRetry: () => void }) {
  const showPri = job.priority != null && job.priority !== 2;
  const deps = parseDeps(job.depends_on);
  const timeLabel = job.started_at ? `Started: ${formatBackendDateTime(job.started_at)}` :
    job.queued_at ? `Queued: ${formatBackendDateTime(job.queued_at)}` : '';
  return (
    <div className="card card-sm" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 'var(--space-4)' }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          {job.playbook_name || 'Unknown'}
          {showPri && (
            <Badge tone={priorityTone(job.priority)}>{priorityLabel(job.priority)}</Badge>
          )}
          {deps.length > 0 && <Badge title={`Depends on jobs: ${deps.join(', ')}`}>deps: {deps.join(', ')}</Badge>}
        </div>
        <div className="text-muted" style={{ fontSize: '0.85rem', marginTop: '0.25rem' }}>
          Group: {job.group_name || 'Unknown'} • {timeLabel} •{' '}
          <StatusBadge status={job.status} size="sm" />
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
