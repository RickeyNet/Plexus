import { StatusBadge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { formatBackendDateTime } from '@/lib/datetime';
import { statusTone, toneColor } from '@/lib/severity';

/**
 * The approval block of a change held for four-eyes review (a deployment or a
 * job): its approval status, who decided and why, and - for a user who may
 * decide - a comment field with the approve and reject/deny buttons.
 */
export interface ApprovalSectionProps {
  /** `pending`, `approved`, `rejected` or `denied` (`not_required` shows only the badge). */
  status: string;
  approvedBy: string;
  approvedAt: string;
  comment: string;
  /** When the approval was requested (shown while pending). */
  requestedAt?: string;
  canApprove: boolean;
  approverInput: string;
  onApproverInput: (v: string) => void;
  isPending: boolean;
  /** Which approval decision is in flight, for the spinner. */
  busyAction: 'approve' | 'reject' | null;
  onApprove: () => void;
  onReject: () => void;
  /** The negative decision's verb: "Reject" (deployments) or "Deny" (jobs). */
  rejectLabel?: string;
  /** Shown while pending to a user who may not decide. */
  pendingNote?: string;
  /** Heading before the badge. */
  heading?: string;
}

export function ApprovalSection({
  status,
  approvedBy,
  approvedAt,
  comment,
  requestedAt,
  canApprove,
  approverInput,
  onApproverInput,
  isPending,
  busyAction,
  onApprove,
  onReject,
  rejectLabel = 'Reject',
  pendingNote = 'Awaiting approval from a user other than the requester.',
  heading = 'Approval gate:',
}: ApprovalSectionProps) {
  const color = toneColor(statusTone(status));
  const decided = status === 'approved' ? 'Approved' : status === 'rejected' ? 'Rejected' : status === 'denied' ? 'Denied' : null;
  return (
    <div
      style={{
        border: `1px solid ${color}`,
        background: 'var(--bg-secondary)',
        padding: '0.75rem',
        borderRadius: 6,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
        <strong>{heading}</strong>
        <StatusBadge status={status} />
        {requestedAt && status === 'pending' && (
          <span style={{ color: 'var(--text-muted)', fontSize: '0.85em' }}>
            requested {formatBackendDateTime(requestedAt, '')}
          </span>
        )}
      </div>
      {decided && (
        <div style={{ marginTop: '0.4rem', fontSize: '0.85em', color: 'var(--text-muted)' }}>
          {decided} by {approvedBy || 'unknown'} at {formatBackendDateTime(approvedAt, '')}.
          {comment && <div>"{comment}"</div>}
        </div>
      )}
      {canApprove && (
        <div style={{ marginTop: '0.5rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <input
            type="text"
            className="form-input"
            placeholder="Optional comment"
            aria-label="Approval comment"
            maxLength={2000}
            value={approverInput}
            onChange={(e) => onApproverInput(e.target.value)}
            style={{ width: '100%' }}
          />
          <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
            <BusyButton
              className="btn btn-secondary btn-sm"
              style={{ border: '1px solid var(--danger)', color: 'var(--danger)' }}
              busy={busyAction === 'reject'}
              disabled={isPending}
              onClick={onReject}
            >
              {rejectLabel}
            </BusyButton>
            <BusyButton
              className="btn btn-primary btn-sm"
              busy={busyAction === 'approve'}
              disabled={isPending}
              onClick={onApprove}
            >
              Approve
            </BusyButton>
          </div>
        </div>
      )}
      {!canApprove && status === 'pending' && (
        <div style={{ marginTop: '0.4rem', fontSize: '0.85em', color: 'var(--text-muted)' }}>{pendingNote}</div>
      )}
    </div>
  );
}
