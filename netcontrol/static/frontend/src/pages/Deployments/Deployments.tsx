import { useMemo, useState } from 'react';

import {
  type Deployment,
  type DeploymentJobStartResult,
  type DeploymentSummary,
  useDeleteDeployment,
  useDeployments,
  useDeploymentSummary,
  useExecuteDeployment,
  useRollbackDeployment,
} from '@/api/deployments';

import { DeploymentCorrelationModal } from './DeploymentCorrelationModal';
import { DeploymentDetailModal } from './DeploymentDetailModal';
import { DeploymentJobStreamModal } from './DeploymentJobStreamModal';
import { NewDeploymentModal } from './NewDeploymentModal';
import {
  canDelete,
  canExecute,
  canRollback,
  filterDeployments,
  formatStamp,
  rollbackStatusColor,
  statusColor,
} from './helpers';

const STATUS_FILTERS = [
  { value: '', label: 'All statuses' },
  { value: 'planning', label: 'Planning' },
  { value: 'executing', label: 'Executing' },
  { value: 'completed', label: 'Completed' },
  { value: 'failed', label: 'Failed' },
  { value: 'rolled-back', label: 'Rolled back' },
];

interface JobStream {
  jobId: string;
  deploymentId: number;
  title: string;
}

export function Deployments() {
  const summary = useDeploymentSummary();
  const deployments = useDeployments(200);

  const [query, setQuery] = useState('');
  const [status, setStatus] = useState('');
  const [showNew, setShowNew] = useState(false);
  const [detailId, setDetailId] = useState<number | null>(null);
  const [correlationId, setCorrelationId] = useState<number | null>(null);
  const [stream, setStream] = useState<JobStream | null>(null);

  const filtered = useMemo(
    () => filterDeployments(deployments.data || [], { query, status }),
    [deployments.data, query, status],
  );

  const startStream = (
    result: DeploymentJobStartResult,
    title: string,
  ) => {
    setStream({ jobId: result.job_id, deploymentId: result.deployment_id, title });
  };

  return (
    <>
      <div
        className="page-header"
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '0.5rem',
          marginBottom: '0.75rem',
        }}
      >
        <h2 style={{ margin: 0 }}>Deployments</h2>
        <div style={{ display: 'flex', gap: '0.4rem' }}>
          <button className="btn btn-sm btn-primary" onClick={() => setShowNew(true)}>
            New Deployment
          </button>
          <button
            className="btn btn-sm btn-secondary"
            onClick={() => {
              summary.refetch();
              deployments.refetch();
            }}
          >
            Refresh
          </button>
        </div>
      </div>

      <SummaryStrip summary={summary.data} />

      <div className="card" style={{ marginTop: '0.75rem', padding: 0, overflow: 'hidden' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.5rem 0.75rem',
            borderBottom: '1px solid var(--border)',
            flexWrap: 'wrap',
          }}
        >
          <select
            className="form-select form-select-sm"
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            style={{ maxWidth: 200 }}
          >
            {STATUS_FILTERS.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </select>
          <input
            className="form-input"
            placeholder="Search name, group, or description…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{ marginLeft: 'auto', maxWidth: 320 }}
          />
        </div>
        <div style={{ padding: '0.75rem' }}>
          <DeploymentList
            items={filtered}
            loading={deployments.isLoading}
            error={deployments.error}
            onView={(id) => setDetailId(id)}
            onNew={() => setShowNew(true)}
            onExecuted={(r) => startStream(r, 'Executing Deployment')}
            onRolledBack={(r) => startStream(r, 'Rolling Back Deployment')}
          />
        </div>
      </div>

      <NewDeploymentModal
        isOpen={showNew}
        onClose={() => setShowNew(false)}
        onCreated={(id) => setDetailId(id)}
      />
      <DeploymentDetailModal
        isOpen={detailId != null}
        onClose={() => setDetailId(null)}
        deploymentId={detailId}
        onExecuted={(r) => {
          setDetailId(null);
          startStream(r, 'Executing Deployment');
        }}
        onRolledBack={(r) => {
          setDetailId(null);
          startStream(r, 'Rolling Back Deployment');
        }}
        onShowCorrelation={(id) => {
          setDetailId(null);
          setCorrelationId(id);
        }}
      />
      <DeploymentJobStreamModal
        isOpen={stream != null}
        onClose={() => setStream(null)}
        jobId={stream?.jobId ?? null}
        deploymentId={stream?.deploymentId ?? null}
        title={stream?.title ?? 'Deployment Job'}
      />
      <DeploymentCorrelationModal
        isOpen={correlationId != null}
        onClose={() => setCorrelationId(null)}
        deploymentId={correlationId}
      />
    </>
  );
}

function SummaryStrip({ summary }: { summary?: DeploymentSummary }) {
  const items: { label: string; value: string }[] = [
    { label: 'Total', value: String(summary?.total ?? '-') },
    { label: 'Completed', value: String(summary?.completed ?? '-') },
    { label: 'Active', value: String(summary?.active ?? '-') },
    { label: 'Rolled back', value: String(summary?.rolled_back ?? '-') },
    { label: 'Failed', value: String(summary?.failed ?? '-') },
  ];
  return (
    <div className="card">
      <div
        className="card-body"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
          gap: '0.5rem',
          padding: '0.75rem',
        }}
      >
        {items.map((it) => (
          <div key={it.label} style={{ display: 'flex', flexDirection: 'column' }}>
            <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{it.label}</span>
            <span style={{ fontWeight: 600 }}>{it.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function DeploymentList({
  items,
  loading,
  error,
  onView,
  onNew,
  onExecuted,
  onRolledBack,
}: {
  items: Deployment[];
  loading: boolean;
  error: unknown;
  onView: (id: number) => void;
  onNew: () => void;
  onExecuted: (r: DeploymentJobStartResult) => void;
  onRolledBack: (r: DeploymentJobStartResult) => void;
}) {
  if (loading) return <p className="text-muted">Loading deployments…</p>;
  if (error) {
    return (
      <p style={{ color: 'var(--danger)' }}>
        Failed to load deployments: {(error as Error).message}
      </p>
    );
  }
  if (!items.length) {
    return (
      <div className="empty-state" style={{ padding: '2rem 1rem', textAlign: 'center' }}>
        <p style={{ color: 'var(--text-muted)', marginBottom: '1rem' }}>No deployments yet.</p>
        <button className="btn btn-primary btn-sm" onClick={onNew}>
          Create Deployment
        </button>
      </div>
    );
  }

  return (
    <>
      {items.map((d) => (
        <DeploymentRow
          key={d.id}
          deployment={d}
          onView={() => onView(d.id)}
          onExecuted={onExecuted}
          onRolledBack={onRolledBack}
        />
      ))}
    </>
  );
}

function DeploymentRow({
  deployment,
  onView,
  onExecuted,
  onRolledBack,
}: {
  deployment: Deployment;
  onView: () => void;
  onExecuted: (r: DeploymentJobStartResult) => void;
  onRolledBack: (r: DeploymentJobStartResult) => void;
}) {
  const execute = useExecuteDeployment();
  const rollback = useRollbackDeployment();
  const remove = useDeleteDeployment();

  const color = statusColor(deployment.status);
  const created = formatStamp(deployment.created_at);
  const finished = formatStamp(deployment.finished_at);

  const handleExecute = () => {
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

  const handleDelete = () => {
    if (!confirm('Delete this deployment and all its checkpoints/snapshots?')) return;
    remove.mutate(deployment.id, {
      onError: (e) => alert((e as Error).message),
    });
  };

  return (
    <div className="card" style={{ marginBottom: '0.75rem', padding: '1rem' }}>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '0.5rem',
        }}
      >
        <div>
          <span
            className="badge"
            style={{
              background: `var(--${color})`,
              color: 'white',
              fontSize: '0.8em',
              padding: '3px 10px',
              borderRadius: 4,
              textTransform: 'uppercase',
              fontWeight: 600,
            }}
          >
            {deployment.status}
          </span>
          {deployment.rollback_status && (
            <span
              style={{
                marginLeft: '0.5rem',
                fontSize: '0.75em',
                color: `var(--${rollbackStatusColor(deployment.rollback_status)})`,
              }}
            >
              (rollback: {deployment.rollback_status})
            </span>
          )}
          <strong style={{ marginLeft: '0.75rem' }}>{deployment.name}</strong>
          <span
            style={{
              marginLeft: '0.5rem',
              fontSize: '0.85em',
              color: 'var(--text-muted)',
            }}
          >
            Group: {deployment.group_name || 'N/A'}
          </span>
        </div>
        <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
          <button className="btn btn-sm btn-secondary" onClick={onView}>
            Details
          </button>
          {canExecute(deployment.status) && (
            <button
              className="btn btn-sm btn-primary"
              disabled={execute.isPending}
              onClick={handleExecute}
            >
              {execute.isPending ? 'Starting…' : 'Execute'}
            </button>
          )}
          {canRollback(deployment.status) && (
            <button
              className="btn btn-sm"
              style={{ color: 'var(--warning)', border: '1px solid var(--warning)' }}
              disabled={rollback.isPending}
              onClick={handleRollback}
            >
              {rollback.isPending ? 'Starting…' : 'Rollback'}
            </button>
          )}
          {canDelete(deployment.status) && (
            <button
              className="btn btn-sm"
              style={{ color: 'var(--danger)' }}
              onClick={handleDelete}
            >
              Delete
            </button>
          )}
        </div>
      </div>
      <div style={{ marginTop: '0.5rem', fontSize: '0.85em', color: 'var(--text-muted)' }}>
        {deployment.description ? `${deployment.description} · ` : ''}
        Type: {deployment.change_type || '?'} · {created || '-'}
        {deployment.created_by ? ` by ${deployment.created_by}` : ''}
        {finished ? ` · Finished: ${finished}` : ''}
      </div>
    </div>
  );
}
