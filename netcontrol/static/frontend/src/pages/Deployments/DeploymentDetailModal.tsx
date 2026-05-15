import { useState } from 'react';

import { useAuthStatus } from '@/api/auth';
import {
  type DeploymentCheckpoint,
  type DeploymentDetail,
  type DeploymentJobStartResult,
  useApproveDeployment,
  useDeployment,
  useExecuteDeployment,
  useRejectDeployment,
  useRequestDeploymentApproval,
  useRollbackDeployment,
} from '@/api/deployments';
import { Modal } from '@/components/Modal';

import {
  canExecute,
  canRollback,
  commandCount,
  formatStamp,
  formatTime,
  rollbackStatusColor,
  statusColor,
} from './helpers';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  deploymentId: number | null;
  onExecuted: (r: DeploymentJobStartResult) => void;
  onRolledBack: (r: DeploymentJobStartResult) => void;
  onShowCorrelation: (id: number) => void;
}

interface MetricDetail {
  metric: string;
  pre?: number | null;
  post?: number | null;
  delta?: number | null;
  concern?: boolean;
}

interface MetricResult {
  details?: MetricDetail[];
}

export function DeploymentDetailModal({
  isOpen,
  onClose,
  deploymentId,
  onExecuted,
  onRolledBack,
  onShowCorrelation,
}: Props) {
  const query = useDeployment(isOpen ? deploymentId : null);

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Deployment Details" size="large">
      {query.isPending && <p className="text-muted">Loading…</p>}
      {query.error && (
        <p style={{ color: 'var(--danger)' }}>
          Failed to load: {(query.error as Error).message}
        </p>
      )}
      {query.data && (
        <DetailBody
          deployment={query.data}
          onClose={onClose}
          onExecuted={onExecuted}
          onRolledBack={onRolledBack}
          onShowCorrelation={onShowCorrelation}
        />
      )}
    </Modal>
  );
}

function DetailBody({
  deployment,
  onClose,
  onExecuted,
  onRolledBack,
  onShowCorrelation,
}: {
  deployment: DeploymentDetail;
  onClose: () => void;
  onExecuted: (r: DeploymentJobStartResult) => void;
  onRolledBack: (r: DeploymentJobStartResult) => void;
  onShowCorrelation: (id: number) => void;
}) {
  const execute = useExecuteDeployment();
  const rollback = useRollbackDeployment();
  const approve = useApproveDeployment();
  const reject = useRejectDeployment();
  const requestApproval = useRequestDeploymentApproval();
  const { data: auth } = useAuthStatus();
  const [approvalComment, setApprovalComment] = useState('');

  const color = statusColor(deployment.status);
  const requiresApproval = !!deployment.requires_approval;
  const approvalStatus = deployment.approval_status || 'not_required';
  const approvalBlocking = requiresApproval && approvalStatus !== 'approved';
  const isApprover =
    !!auth?.username &&
    auth.username !== (deployment.created_by || '');
  const checkpoints = deployment.checkpoints || [];
  const snapshots = deployment.snapshots || [];
  const preChecks = checkpoints.filter((c) => c.phase === 'pre');
  const postChecks = checkpoints.filter((c) => c.phase === 'post');
  const rollbackChecks = checkpoints.filter((c) => c.phase === 'rollback');
  const verifyChecks = checkpoints.filter((c) => c.phase === 'verify');
  const preSnaps = snapshots.filter((s) => s.phase === 'pre');
  const postSnaps = snapshots.filter((s) => s.phase === 'post');

  const handleExecute = () => {
    if (approvalBlocking) {
      alert('This deployment is awaiting approval and cannot be executed.');
      return;
    }
    if (
      !confirm(
        'Execute this deployment? Pre-deployment snapshots will be captured before pushing config changes.',
      )
    )
      return;
    execute.mutate(deployment.id, {
      onSuccess: onExecuted,
      onError: (e) => alert((e as Error).message),
    });
  };

  const handleRollback = () => {
    if (
      !confirm(
        'Roll back this deployment? Pre-deployment config snapshots will be restored to all hosts.',
      )
    )
      return;
    rollback.mutate(deployment.id, {
      onSuccess: onRolledBack,
      onError: (e) => alert((e as Error).message),
    });
  };

  return (
    <>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
          <div>
            <strong>Status:</strong>{' '}
            <span
              style={{
                color: `var(--${color})`,
                fontWeight: 600,
                textTransform: 'uppercase',
              }}
            >
              {deployment.status}
            </span>
          </div>
          <div>
            <strong>Group:</strong> {deployment.group_name || 'N/A'}
          </div>
          <div>
            <strong>Type:</strong> {deployment.change_type || '?'}
          </div>
          {deployment.rollback_status && (
            <div>
              <strong>Rollback:</strong>{' '}
              <span style={{ color: `var(--${rollbackStatusColor(deployment.rollback_status)})` }}>
                {deployment.rollback_status}
              </span>
            </div>
          )}
        </div>

        <div
          style={{
            display: 'flex',
            gap: '1rem',
            flexWrap: 'wrap',
            fontSize: '0.85em',
            color: 'var(--text-muted)',
          }}
        >
          <span>Created: {formatStamp(deployment.created_at) || '-'}</span>
          <span>Started: {formatStamp(deployment.started_at) || '-'}</span>
          <span>Finished: {formatStamp(deployment.finished_at) || '-'}</span>
          {deployment.created_by && <span>By: {deployment.created_by}</span>}
        </div>

        {deployment.description && (
          <div style={{ fontSize: '0.9em' }}>{deployment.description}</div>
        )}

        {requiresApproval && (
          <ApprovalSection
            status={approvalStatus}
            approvedBy={deployment.approved_by || ''}
            approvedAt={deployment.approved_at || ''}
            comment={deployment.approval_comment || ''}
            requestedAt={deployment.approval_requested_at || ''}
            canApprove={isApprover && approvalStatus === 'pending'}
            approverInput={approvalComment}
            onApproverInput={setApprovalComment}
            isPending={approve.isPending || reject.isPending}
            onApprove={() =>
              approve.mutate(
                { id: deployment.id, comment: approvalComment },
                { onError: (e) => alert((e as Error).message) },
              )
            }
            onReject={() => {
              if (!confirm('Reject this deployment? It will need a fresh approval request.')) return;
              reject.mutate(
                { id: deployment.id, comment: approvalComment },
                { onError: (e) => alert((e as Error).message) },
              );
            }}
          />
        )}

        {!requiresApproval && canExecute(deployment.status) && (
          <div style={{ fontSize: '0.85em' }}>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              disabled={requestApproval.isPending}
              onClick={() =>
                requestApproval.mutate(deployment.id, {
                  onError: (e) => alert((e as Error).message),
                })
              }
            >
              {requestApproval.isPending ? 'Requesting…' : 'Request approval gate'}
            </button>
          </div>
        )}

        <details>
          <summary style={{ cursor: 'pointer', fontWeight: 600 }}>
            Proposed Commands ({commandCount(deployment.proposed_commands)})
          </summary>
          <pre
            style={{
              marginTop: '0.5rem',
              background: 'var(--bg-secondary)',
              padding: '0.75rem',
              borderRadius: 6,
              fontSize: '0.82rem',
              maxHeight: 200,
              overflowY: 'auto',
              whiteSpace: 'pre-wrap',
            }}
          >
            {deployment.proposed_commands || ''}
          </pre>
        </details>

        <CheckpointSection title="Pre-Deployment Checkpoints" checks={preChecks} label="pre-deployment" />
        <CheckpointSection title="Post-Deployment Checkpoints" checks={postChecks} label="post-deployment" />
        {rollbackChecks.length > 0 && (
          <CheckpointSection title="Rollback Checkpoints" checks={rollbackChecks} label="rollback" />
        )}
        {verifyChecks.length > 0 && (
          <div>
            <h4 style={{ margin: '0 0 0.5rem' }}>Verification</h4>
            <CheckpointTable checks={verifyChecks} label="verification" />
            <VerificationMetricsTable checks={verifyChecks} />
          </div>
        )}

        <div style={{ display: 'flex', gap: '0.75rem', fontSize: '0.85em', color: 'var(--text-muted)' }}>
          <span>Pre-snapshots: {preSnaps.length}</span>
          <span>Post-snapshots: {postSnaps.length}</span>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
          {canExecute(deployment.status) && (
            <button
              type="button"
              className="btn btn-primary"
              disabled={execute.isPending || approvalBlocking}
              title={approvalBlocking ? 'Waiting on approval' : undefined}
              onClick={handleExecute}
            >
              {execute.isPending ? 'Starting…' : 'Execute'}
            </button>
          )}
          {canRollback(deployment.status) && (
            <button
              type="button"
              className="btn btn-secondary"
              style={{ border: '1px solid var(--warning)', color: 'var(--warning)' }}
              disabled={rollback.isPending}
              onClick={handleRollback}
            >
              {rollback.isPending ? 'Starting…' : 'Rollback'}
            </button>
          )}
          {deployment.started_at && (
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => onShowCorrelation(deployment.id)}
            >
              Correlation
            </button>
          )}
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </>
  );
}

function ApprovalSection({
  status,
  approvedBy,
  approvedAt,
  comment,
  requestedAt,
  canApprove,
  approverInput,
  onApproverInput,
  isPending,
  onApprove,
  onReject,
}: {
  status: string;
  approvedBy: string;
  approvedAt: string;
  comment: string;
  requestedAt: string;
  canApprove: boolean;
  approverInput: string;
  onApproverInput: (v: string) => void;
  isPending: boolean;
  onApprove: () => void;
  onReject: () => void;
}) {
  const color =
    status === 'approved' ? 'success' :
    status === 'rejected' ? 'danger' :
    status === 'pending' ? 'warning' :
    'text-muted';
  return (
    <div
      style={{
        border: `1px solid var(--${color})`,
        background: 'var(--bg-secondary)',
        padding: '0.75rem',
        borderRadius: 6,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
        <strong>Approval gate:</strong>
        <span style={{ color: `var(--${color})`, textTransform: 'uppercase', fontWeight: 600 }}>
          {status}
        </span>
        {requestedAt && status === 'pending' && (
          <span style={{ color: 'var(--text-muted)', fontSize: '0.85em' }}>
            requested {formatStamp(requestedAt)}
          </span>
        )}
      </div>
      {status === 'approved' && (
        <div style={{ marginTop: '0.4rem', fontSize: '0.85em', color: 'var(--text-muted)' }}>
          Approved by {approvedBy || 'unknown'} at {formatStamp(approvedAt)}.
          {comment && <div>"{comment}"</div>}
        </div>
      )}
      {status === 'rejected' && (
        <div style={{ marginTop: '0.4rem', fontSize: '0.85em', color: 'var(--text-muted)' }}>
          Rejected by {approvedBy || 'unknown'} at {formatStamp(approvedAt)}.
          {comment && <div>"{comment}"</div>}
        </div>
      )}
      {canApprove && (
        <div style={{ marginTop: '0.5rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <input
            type="text"
            className="input"
            placeholder="Optional comment"
            value={approverInput}
            onChange={(e) => onApproverInput(e.target.value)}
            style={{ width: '100%' }}
          />
          <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              style={{ border: '1px solid var(--danger)', color: 'var(--danger)' }}
              disabled={isPending}
              onClick={onReject}
            >
              Reject
            </button>
            <button
              type="button"
              className="btn btn-primary btn-sm"
              disabled={isPending}
              onClick={onApprove}
            >
              {isPending ? 'Saving…' : 'Approve'}
            </button>
          </div>
        </div>
      )}
      {!canApprove && status === 'pending' && (
        <div style={{ marginTop: '0.4rem', fontSize: '0.85em', color: 'var(--text-muted)' }}>
          This deployment is awaiting approval from a user other than the creator.
        </div>
      )}
    </div>
  );
}


function CheckpointSection({
  title,
  checks,
  label,
}: {
  title: string;
  checks: DeploymentCheckpoint[];
  label: string;
}) {
  return (
    <div>
      <h4 style={{ margin: '0 0 0.5rem' }}>{title}</h4>
      <CheckpointTable checks={checks} label={label} />
    </div>
  );
}

function CheckpointTable({
  checks,
  label,
}: {
  checks: DeploymentCheckpoint[];
  label: string;
}) {
  if (!checks.length) {
    return (
      <div style={{ color: 'var(--text-muted)', fontSize: '0.85em' }}>
        No {label} checkpoints.
      </div>
    );
  }
  return (
    <table style={{ width: '100%', fontSize: '0.85em', borderCollapse: 'collapse' }}>
      <thead>
        <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--border)' }}>
          <th style={{ padding: '4px 8px' }}>Host</th>
          <th style={{ padding: '4px 8px' }}>Check</th>
          <th style={{ padding: '4px 8px' }}>Status</th>
          <th style={{ padding: '4px 8px' }}>Time</th>
        </tr>
      </thead>
      <tbody>
        {checks.map((c) => {
          const cpColor =
            c.status === 'passed' ? 'success' : c.status === 'failed' ? 'danger' : 'text-muted';
          return (
            <tr key={c.id} style={{ borderBottom: '1px solid var(--border)' }}>
              <td style={{ padding: '4px 8px' }}>{c.hostname || c.ip_address || '-'}</td>
              <td style={{ padding: '4px 8px' }}>{c.check_type}</td>
              <td style={{ padding: '4px 8px' }}>
                <span
                  style={{
                    color: `var(--${cpColor})`,
                    fontWeight: 600,
                    textTransform: 'uppercase',
                  }}
                >
                  {c.status}
                </span>
              </td>
              <td style={{ padding: '4px 8px' }}>{formatTime(c.executed_at) || '-'}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function VerificationMetricsTable({ checks }: { checks: DeploymentCheckpoint[] }) {
  const healthChecks = checks.filter((c) => c.check_type === 'metric_health');
  const rows: Array<{
    host: string;
    metric: string;
    pre: string;
    post: string;
    delta: string;
    concern: boolean;
  }> = [];

  for (const cp of healthChecks) {
    let parsed: MetricResult;
    try {
      parsed = JSON.parse(cp.result || '{}') as MetricResult;
    } catch {
      continue;
    }
    for (const m of parsed.details || []) {
      const preStr = m.pre != null ? m.pre.toFixed(1) : 'N/A';
      const postStr = m.post != null ? m.post.toFixed(1) : 'N/A';
      const deltaStr =
        m.delta != null
          ? m.delta >= 0
            ? `+${m.delta.toFixed(1)}`
            : m.delta.toFixed(1)
          : '-';
      rows.push({
        host: cp.hostname || cp.ip_address || '-',
        metric: m.metric,
        pre: preStr,
        post: postStr,
        delta: deltaStr,
        concern: !!m.concern,
      });
    }
  }

  if (!rows.length) return null;

  return (
    <table
      style={{
        width: '100%',
        fontSize: '0.85em',
        borderCollapse: 'collapse',
        marginTop: '0.5rem',
      }}
    >
      <thead>
        <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--border)' }}>
          <th style={{ padding: '4px 8px' }}>Host</th>
          <th style={{ padding: '4px 8px' }}>Metric</th>
          <th style={{ padding: '4px 8px' }}>Pre</th>
          <th style={{ padding: '4px 8px' }}>Post</th>
          <th style={{ padding: '4px 8px' }}>Delta</th>
          <th style={{ padding: '4px 8px' }}>Status</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
            <td style={{ padding: '4px 8px' }}>{r.host}</td>
            <td style={{ padding: '4px 8px' }}>{r.metric}</td>
            <td style={{ padding: '4px 8px' }}>{r.pre}</td>
            <td style={{ padding: '4px 8px' }}>{r.post}</td>
            <td
              style={{
                padding: '4px 8px',
                color: r.concern ? 'var(--danger)' : 'var(--success)',
                fontWeight: 600,
              }}
            >
              {r.delta}
            </td>
            <td style={{ padding: '4px 8px' }}>
              {r.concern ? (
                <span style={{ color: 'var(--danger)' }}>CONCERN</span>
              ) : (
                <span style={{ color: 'var(--success)' }}>OK</span>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
