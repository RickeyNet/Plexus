import { useState } from 'react';

import {
  type AlertCorrelation,
  useAlertCorrelation,
} from '@/api/deployments';
import { Modal } from '@/components/Modal';
import { DeploymentCorrelationModal } from '@/pages/Deployments/DeploymentCorrelationModal';
import { formatStamp } from '@/pages/Deployments/helpers';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  alertId: number | null;
}

export function AlertCorrelationModal({ isOpen, onClose, alertId }: Props) {
  const query = useAlertCorrelation(isOpen ? alertId : null);
  const [deploymentId, setDeploymentId] = useState<number | null>(null);

  const title = query.data
    ? `Alert Correlation — ${
        query.data.alert.metric ||
        query.data.alert.alert_type ||
        'Alert'
      }`
    : 'Alert Correlation';

  return (
    <>
      <Modal isOpen={isOpen} onClose={onClose} title={title} size="large">
        {query.isPending && <p className="text-muted">Loading…</p>}
        {query.error && (
          <p style={{ color: 'var(--danger)' }}>
            Failed to load: {(query.error as Error).message}
          </p>
        )}
        {query.data && (
          <Body
            data={query.data}
            onClose={onClose}
            onOpenDeployment={(id) => setDeploymentId(id)}
          />
        )}
      </Modal>
      <DeploymentCorrelationModal
        isOpen={deploymentId != null}
        onClose={() => setDeploymentId(null)}
        deploymentId={deploymentId}
      />
    </>
  );
}

function Body({
  data,
  onClose,
  onOpenDeployment,
}: {
  data: AlertCorrelation;
  onClose: () => void;
  onOpenDeployment: (id: number) => void;
}) {
  const { alert, related_deployments, related_drift_events } = data;
  const sevColor =
    alert.severity === 'critical' ? 'var(--danger)' : 'var(--warning)';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div className="card" style={{ padding: '1rem' }}>
        <div
          style={{
            display: 'flex',
            gap: '1rem',
            flexWrap: 'wrap',
            fontSize: '0.9em',
          }}
        >
          <span>
            <strong>Host:</strong> {alert.hostname || ''}
          </span>
          <span>
            <strong>Severity:</strong>{' '}
            <span style={{ color: sevColor }}>{alert.severity || 'unknown'}</span>
          </span>
          <span>
            <strong>Value:</strong> {alert.value != null ? alert.value : '-'}
          </span>
          <span>
            <strong>Time:</strong> {formatStamp(alert.created_at) || '-'}
          </span>
        </div>
        {alert.message && (
          <div
            style={{
              marginTop: '0.5rem',
              color: 'var(--text-muted)',
              fontSize: '0.85em',
            }}
          >
            {alert.message}
          </div>
        )}
      </div>

      <div>
        <h4 style={{ margin: '0 0 0.5rem' }}>
          Possibly Related Deployments (30 min window)
        </h4>
        {related_deployments.length === 0 ? (
          <div style={{ color: 'var(--text-muted)' }}>
            No related deployments found.
          </div>
        ) : (
          related_deployments.map((dep) => (
            <div
              key={dep.id}
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '0.4rem 0',
                borderBottom: '1px solid var(--border)',
              }}
            >
              <div>
                <div style={{ fontWeight: 600 }}>
                  {dep.name || `Deployment #${dep.id}`}
                </div>
                <div style={{ fontSize: '0.85em', color: 'var(--text-muted)' }}>
                  {dep.status || ''} — {formatStamp(dep.started_at)}
                </div>
              </div>
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                onClick={() => onOpenDeployment(dep.id)}
              >
                View Correlation
              </button>
            </div>
          ))
        )}
      </div>

      <div>
        <h4 style={{ margin: '0 0 0.5rem' }}>Related Config Drift</h4>
        {related_drift_events.length === 0 ? (
          <div style={{ color: 'var(--text-muted)' }}>
            No related drift events found.
          </div>
        ) : (
          related_drift_events.map((d, i) => (
            <div
              key={i}
              style={{
                padding: '0.4rem 0',
                borderBottom: '1px solid var(--border)',
              }}
            >
              <div style={{ fontWeight: 600 }}>
                {d.hostname || `Host #${d.host_id}`} — Config Drift
              </div>
              <div style={{ fontSize: '0.85em', color: 'var(--text-muted)' }}>
                +{d.diff_lines_added || 0}/-{d.diff_lines_removed || 0} lines —{' '}
                {formatStamp(d.detected_at)}
              </div>
            </div>
          ))
        )}
      </div>

      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <button type="button" className="btn btn-secondary" onClick={onClose}>
          Close
        </button>
      </div>
    </div>
  );
}
