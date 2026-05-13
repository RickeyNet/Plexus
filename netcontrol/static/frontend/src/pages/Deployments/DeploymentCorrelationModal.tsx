import { useMemo } from 'react';

import { type DeploymentCorrelation, useDeploymentCorrelation } from '@/api/deployments';
import { Modal } from '@/components/Modal';

import { formatStamp, formatTime } from './helpers';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  deploymentId: number | null;
}

interface TimelineEvent {
  time?: string | null;
  type: 'deployment' | 'drift' | 'alert' | 'audit';
  icon: string;
  title: string;
  detail: string;
  color: string;
}

export function DeploymentCorrelationModal({ isOpen, onClose, deploymentId }: Props) {
  const query = useDeploymentCorrelation(isOpen ? deploymentId : null);

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Deployment Correlation" size="large">
      {query.isPending && <p className="text-muted">Loading…</p>}
      {query.error && (
        <p style={{ color: 'var(--danger)' }}>
          Failed to load: {(query.error as Error).message}
        </p>
      )}
      {query.data && <CorrelationBody data={query.data} onClose={onClose} />}
    </Modal>
  );
}

function CorrelationBody({
  data,
  onClose,
}: {
  data: DeploymentCorrelation;
  onClose: () => void;
}) {
  const events = useMemo(() => buildTimeline(data), [data]);
  const windowStart = formatStamp(data.time_window?.start) || '?';
  const windowEnd = formatStamp(data.time_window?.end) || '?';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ fontSize: '0.85em', color: 'var(--text-muted)' }}>
        Time window: {windowStart} - {windowEnd}
        <span style={{ marginLeft: '1rem' }}>Events: {events.length}</span>
      </div>
      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', fontSize: '0.8em' }}>
        <span style={{ color: '#3b82f6' }}>● Deployment</span>
        <span style={{ color: 'var(--warning)' }}>● Drift</span>
        <span style={{ color: 'var(--danger)' }}>● Alert</span>
        <span style={{ color: 'var(--text-muted)' }}>● Audit</span>
      </div>
      <div
        style={{
          maxHeight: 400,
          overflowY: 'auto',
          border: '1px solid var(--border)',
          borderRadius: '0.5rem',
          padding: '0.5rem',
        }}
      >
        {events.length ? (
          events.map((e, i) => <TimelineRow key={i} event={e} />)
        ) : (
          <div style={{ color: 'var(--text-muted)', padding: '1rem' }}>
            No correlated events found in the time window.
          </div>
        )}
      </div>
      <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
        <button type="button" className="btn btn-secondary" onClick={onClose}>
          Close
        </button>
      </div>
    </div>
  );
}

function TimelineRow({ event }: { event: TimelineEvent }) {
  return (
    <div
      style={{
        display: 'flex',
        gap: '0.75rem',
        padding: '0.35rem 0',
        borderBottom: '1px solid var(--border)',
        fontSize: '0.85em',
      }}
    >
      <span style={{ minWidth: 60, color: 'var(--text-muted)' }}>
        {formatTime(event.time)}
      </span>
      <span style={{ color: event.color, minWidth: 20, textAlign: 'center' }}>{event.icon}</span>
      <div>
        <div style={{ fontWeight: 600 }}>{event.title}</div>
        <div style={{ color: 'var(--text-muted)', fontSize: '0.9em' }}>{event.detail}</div>
      </div>
    </div>
  );
}

function buildTimeline(data: DeploymentCorrelation): TimelineEvent[] {
  const events: TimelineEvent[] = [];

  for (const cp of data.checkpoints || []) {
    events.push({
      time: cp.executed_at || cp.created_at,
      type: 'deployment',
      icon: cp.status === 'passed' ? '✓' : cp.status === 'failed' ? '✗' : '○',
      title: `${cp.phase}: ${cp.check_type}`,
      detail: `${cp.hostname || ''} - ${cp.status}`,
      color:
        cp.status === 'passed'
          ? 'var(--success)'
          : cp.status === 'failed'
            ? 'var(--danger)'
            : 'var(--text-muted)',
    });
  }

  for (const drift of data.drift_events || []) {
    events.push({
      time: drift.detected_at,
      type: 'drift',
      icon: '⚠',
      title: 'Config Drift Detected',
      detail: `${drift.hostname || `Host #${drift.host_id}`} - +${drift.diff_lines_added || 0}/-${
        drift.diff_lines_removed || 0
      } lines`,
      color: 'var(--warning)',
    });
  }

  for (const alert of data.alerts || []) {
    events.push({
      time: alert.created_at,
      type: 'alert',
      icon: '●',
      title: `Alert: ${alert.metric || alert.alert_type || 'unknown'}`,
      detail: `${alert.hostname || ''} - ${alert.message || ''}`.trim(),
      color: alert.severity === 'critical' ? 'var(--danger)' : 'var(--warning)',
    });
  }

  for (const ae of data.audit_trail || []) {
    events.push({
      time: ae.timestamp,
      type: 'audit',
      icon: '▸',
      title: ae.action,
      detail: ae.detail || '',
      color: 'var(--text-muted)',
    });
  }

  events.sort((a, b) => (a.time || '').localeCompare(b.time || ''));
  return events;
}
