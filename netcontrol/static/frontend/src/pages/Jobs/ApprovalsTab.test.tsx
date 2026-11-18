import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { Job } from '@/api/jobs';
import { ApprovalSection } from '@/components/ApprovalSection';
import { statusTone } from '@/lib/severity';

import { ApprovalsTab } from './ApprovalsTab';
import { isJobCancellable, isJobFinished, isJobRetryable, jobTargetLabel } from './helpers';

const state = vi.hoisted(() => ({ approvals: {} as Record<string, unknown> }));

const mutation = { isPending: false, mutate: () => {} };

vi.mock('@/api/jobs', () => ({
  useJobApprovals: () => state.approvals,
  useApproveJob: () => mutation,
  useDenyJob: () => mutation,
}));
vi.mock('@/components/DialogProvider-context', () => ({
  useDialogs: () => ({ confirm: async () => true, alert: async () => {} }),
}));

const query = (over: Record<string, unknown>) => ({
  isError: false,
  isPending: false,
  isFetching: false,
  data: undefined,
  error: null,
  refetch: () => {},
  ...over,
});

const PENDING: Job = {
  id: 41,
  playbook_name: 'vlan-push',
  group_name: 'branch-switches',
  status: 'pending_approval',
  approval_status: 'pending',
  dry_run: false,
  launched_by: 'operator-a',
  queued_at: '2026-11-14 08:00:00',
  parameters: '{"vlan": 120}',
};

describe('job status helpers', () => {
  it('treats a job awaiting approval as unfinished and cancellable', () => {
    expect(isJobCancellable('pending_approval')).toBe(true);
    expect(isJobCancellable('queued')).toBe(true);
    expect(isJobCancellable('denied')).toBe(false);
    expect(isJobFinished('pending_approval')).toBe(false);
    expect(isJobFinished('denied')).toBe(true);
    expect(isJobFinished('')).toBe(false);
  });

  it('retries failed, cancelled and denied jobs', () => {
    expect(['failed', 'cancelled', 'denied'].every(isJobRetryable)).toBe(true);
    expect(isJobRetryable('pending_approval')).toBe(false);
    expect(isJobRetryable('success')).toBe(false);
  });

  it('labels the target', () => {
    expect(jobTargetLabel({ group_name: 'core' })).toBe('Group: core');
    expect(jobTargetLabel({ dynamic_group_name: 'all-edge' })).toBe('Dynamic group: all-edge');
    expect(jobTargetLabel({})).toBe('Group: Unknown');
  });

  it('colours the approval statuses', () => {
    expect(statusTone('pending_approval')).toBe('warning');
    expect(statusTone('denied')).toBe('danger');
  });
});

describe('ApprovalsTab', () => {
  beforeEach(() => {
    state.approvals = query({ data: [PENDING] });
  });

  it('lists each pending job with approve and deny', () => {
    const html = renderToStaticMarkup(<ApprovalsTab />);
    expect(html).toContain('#41 vlan-push');
    expect(html).toContain('Group: branch-switches');
    expect(html).toContain('requested by operator-a');
    expect(html).toContain('Commit');
    expect(html).toContain('Inputs:');
    expect(html).toContain('aria-label="Approval comment"');
    expect(html).toContain('>Approve<');
    expect(html).toContain('>Deny<');
  });

  it('says when nothing waits', () => {
    state.approvals = query({ data: [] });
    expect(renderToStaticMarkup(<ApprovalsTab />)).toContain('No jobs are waiting for your approval');
  });

  it('shows the load error', () => {
    state.approvals = query({ isError: true, error: new Error('Access denied'), data: undefined });
    expect(renderToStaticMarkup(<ApprovalsTab />)).not.toContain('>Approve<');
  });
});

describe('ApprovalSection', () => {
  const base = {
    approvedBy: 'approver-b',
    approvedAt: '2026-11-14 09:00:00',
    comment: 'outside the window',
    canApprove: false,
    approverInput: '',
    onApproverInput: () => {},
    isPending: false,
    busyAction: null,
    onApprove: () => {},
    onReject: () => {},
  } as const;

  it('records a denial with who and why', () => {
    const html = renderToStaticMarkup(<ApprovalSection {...base} status="denied" />);
    expect(html).toContain('Denied by approver-b');
    expect(html).toContain('outside the window');
    expect(html).not.toContain('aria-label="Approval comment"');
  });

  it('explains a pending approval to someone who cannot decide it', () => {
    const html = renderToStaticMarkup(<ApprovalSection {...base} status="pending" pendingNote="Waiting for another approver." />);
    expect(html).toContain('Waiting for another approver.');
  });
});
