import { Link } from 'react-router';

import type { DashboardAlert, TopologyProblem } from '@/api/dashboard';
import { Badge, SeverityBadge } from '@/components/Badge';
import { formatBackendDateTime, formatRelativeTime } from '@/lib/datetime';

import { TOPOLOGY_AVAILABILITY_LINK, describeProblem, problemLocation } from './sourceHealth';

interface Props {
  alerts: DashboardAlert[];
  /** Down / degraded integration entities (worst first); absent without the monitoring feature. */
  topologyProblems?: TopologyProblem[];
  /** How many there are in all; `topologyProblems` may hold fewer. */
  topologyProblemCount?: number;
}

const TOPOLOGY_ROWS = 20;

export function AlertsSection({ alerts, topologyProblems = [], topologyProblemCount }: Props) {
  const problemTotal = Math.max(topologyProblemCount ?? 0, topologyProblems.length);
  return (
    <div className="glass-card card dashboard-overview-card">
      <h3 className="dashboard-overview-title">Active Alerts</h3>
      {alerts.length === 0 && topologyProblems.length === 0 ? (
        <div style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-muted)' }}>
          <svg
            width="40"
            height="40"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={1.5}
            style={{ opacity: 0.4, marginBottom: '0.5rem' }}
          >
            <polyline points="20 6 9 17 4 12" />
          </svg>
          <p style={{ margin: 0 }}>No active alerts &mdash; all systems nominal</p>
        </div>
      ) : (
        <>
          {alerts.slice(0, 20).map((a, i) => {
            const sev = (a.severity ?? 'info').toLowerCase();
            return (
              <div className="dashboard-alert-item" key={`${a.created_at ?? ''}-${i}`}>
                <SeverityBadge severity={sev} size="sm" />
                <span className="dashboard-alert-host">{a.hostname ?? '-'}</span>
                <span className="dashboard-alert-msg">{a.message ?? a.metric ?? '-'}</span>
                <span className="dashboard-alert-time">{a.created_at ? formatRelativeTime(a.created_at) : ''}</span>
              </div>
            );
          })}
          {topologyProblems.length > 0 && (
            <>
              <h4 style={{ margin: '1rem 0 0.25rem', fontSize: '0.95em' }}>
                Integrations and cloud{' '}
                <span className="text-muted" style={{ fontWeight: 'normal', fontSize: '0.9em' }}>
                  ({problemTotal} down or degraded)
                </span>
              </h4>
              {topologyProblems.slice(0, TOPOLOGY_ROWS).map((p) => (
                <div
                  className="dashboard-alert-item"
                  key={`${p.provider}:${p.org_ref}:${p.entity_type}:${p.entity_id}`}
                  title={describeProblem(p)}
                >
                  <Badge tone={p.state === 'down' ? 'danger' : 'warning'} solid={p.state === 'down'} size="sm">
                    {p.state}
                  </Badge>
                  <span className="dashboard-alert-host">
                    {p.provider_label} {p.type_label}
                  </span>
                  <span className="dashboard-alert-msg">
                    {p.name}
                    {problemLocation(p) ? ` ${problemLocation(p)}` : ''}
                    {p.raw_status && p.raw_status !== p.state ? ` - ${p.raw_status}` : ''}
                  </span>
                  <span
                    className="dashboard-alert-time"
                    title={p.since ? `${p.state} since ${formatBackendDateTime(p.since)}` : undefined}
                  >
                    {p.since ? formatRelativeTime(p.since) : ''}
                  </span>
                </div>
              ))}
              {problemTotal > TOPOLOGY_ROWS && (
                <div style={{ marginTop: '0.5rem', fontSize: '0.85em' }}>
                  <Link to={TOPOLOGY_AVAILABILITY_LINK}>
                    View all {problemTotal} in Monitoring &rarr; Availability
                  </Link>
                </div>
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}
