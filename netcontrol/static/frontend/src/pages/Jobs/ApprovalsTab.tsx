import { useState } from 'react';

import { useApproveJob, useDenyJob, useJobApprovals, type Job } from '@/api/jobs';
import { ApprovalSection } from '@/components/ApprovalSection';
import { Badge } from '@/components/Badge';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { formatBackendDateTime } from '@/lib/datetime';

import { jobTargetLabel } from './helpers';
import { formatJobInputs } from './jobInputs';

/**
 * Jobs awaiting approval that the signed-in user may decide (the server
 * leaves out their own jobs and jobs outside their object scope).
 */
export function ApprovalsTab() {
  const approvals = useJobApprovals();

  if (approvals.error && !approvals.data) return <QueryError what="jobs awaiting approval" query={approvals} />;
  if (approvals.isPending) return <LoadingState />;
  const jobs = approvals.data ?? [];
  if (jobs.length === 0) {
    return (
      <EmptyState
        message="No jobs are waiting for your approval"
        description="Jobs launched from a task that requires approval appear here. Your own jobs need another approver."
      />
    );
  }
  return (
    <div className="stack">
      {jobs.map((job) => (
        <ApprovalRow key={job.id} job={job} />
      ))}
    </div>
  );
}

export function ApprovalRow({ job }: { job: Job }) {
  const { confirm, alert } = useDialogs();
  const approve = useApproveJob();
  const deny = useDenyJob();
  const [comment, setComment] = useState('');
  const isDry = Boolean(job.dry_run);
  const name = job.playbook_name || `Job #${job.id}`;
  const inputs = formatJobInputs(job.parameters);
  const onError = (e: unknown) => void alert({ message: (e as Error).message, variant: 'error' });

  async function handleApprove() {
    const ok = await confirm({
      title: `Approve job #${job.id}`,
      message: `Approve "${name}" requested by ${job.launched_by || 'unknown'}? It joins the queue and runs ${isDry ? 'as a dry run' : 'live, applying changes to devices'}.`,
      confirmLabel: 'Approve',
      confirmVariant: 'primary',
    });
    if (!ok) return;
    approve.mutate({ id: job.id, comment }, { onError });
  }

  async function handleDeny() {
    const ok = await confirm({
      title: `Deny job #${job.id}`,
      message: `Deny "${name}" requested by ${job.launched_by || 'unknown'}? The job ends as denied and never runs; the requester can retry it to ask again.`,
      confirmLabel: 'Deny job',
      confirmVariant: 'danger',
    });
    if (!ok) return;
    deny.mutate({ id: job.id, comment }, { onError });
  }

  return (
    <div className="card card-sm">
      <div style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
        #{job.id} {name}
        <Badge tone={isDry ? 'warning' : 'danger'} solid>
          {isDry ? 'Dry run' : 'Commit'}
        </Badge>
      </div>
      <div className="text-muted" style={{ fontSize: '0.85rem', margin: '0.25rem 0 0.5rem' }}>
        {jobTargetLabel(job)} • requested by {job.launched_by || 'unknown'}
        {job.queued_at && <> • {formatBackendDateTime(job.queued_at)}</>}
      </div>
      {inputs && (
        <div className="text-muted" style={{ fontSize: '0.85rem', marginBottom: '0.5rem', overflowWrap: 'anywhere' }}>
          Inputs: {inputs}
        </div>
      )}
      <ApprovalSection
        heading="Approval:"
        status={job.approval_status || 'pending'}
        approvedBy={job.approved_by || ''}
        approvedAt={job.approved_at || ''}
        comment={job.approval_comment || ''}
        canApprove
        approverInput={comment}
        onApproverInput={setComment}
        isPending={approve.isPending || deny.isPending}
        busyAction={approve.isPending ? 'approve' : deny.isPending ? 'reject' : null}
        onApprove={() => void handleApprove()}
        onReject={() => void handleDeny()}
        rejectLabel="Deny"
      />
    </div>
  );
}
