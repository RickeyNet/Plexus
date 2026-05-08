import type { DashboardAlert } from '@/api/dashboard';

import { timeAgo } from './helpers';

export function AlertsSection({ alerts }: { alerts: DashboardAlert[] }) {
  return (
    <div className="section">
      <h3>Active Alerts</h3>
      {alerts.length === 0 ? (
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
        alerts.slice(0, 20).map((a, i) => {
          const sev = (a.severity ?? 'info').toLowerCase();
          return (
            <div className="dashboard-alert-item" key={`${a.created_at ?? ''}-${i}`}>
              <span className={`alert-severity-badge ${sev}`}>{sev}</span>
              <span className="dashboard-alert-host">{a.hostname ?? '-'}</span>
              <span className="dashboard-alert-msg">{a.message ?? a.metric ?? '-'}</span>
              <span className="dashboard-alert-time">{a.created_at ? timeAgo(a.created_at) : ''}</span>
            </div>
          );
        })
      )}
    </div>
  );
}
