import { useDashboard } from '@/api/dashboard';

import { AlertsSection } from './AlertsSection';
import { HealthSection } from './HealthSection';
import { StatRings } from './StatRings';

export function Dashboard() {
  const { data, isPending, error } = useDashboard();

  if (isPending) {
    return (
      <>
        <h2>Dashboard</h2>
        <div className="stats-grid">
          <div className="skeleton skeleton-card" />
          <div className="skeleton skeleton-card" />
          <div className="skeleton skeleton-card" />
        </div>
        <div className="section">
          <div className="skeleton skeleton-card" />
          <div className="skeleton skeleton-card" />
        </div>
      </>
    );
  }

  if (error) {
    return (
      <>
        <h2>Dashboard</h2>
        <div className="glass-card card" style={{ borderColor: 'var(--danger)' }}>
          <strong>Failed to load dashboard:</strong> {(error as Error).message}
        </div>
      </>
    );
  }

  const stats = data?.stats ?? {};
  const groups = data?.groups ?? [];
  const monitoring = data?.monitoring ?? {};
  const devices = data?.device_health ?? [];
  const alerts = data?.open_alerts ?? [];

  return (
    <>
      <h2>Dashboard</h2>
      <StatRings
        hosts={stats.total_hosts ?? 0}
        playbooks={stats.total_playbooks ?? 0}
        jobs={stats.total_jobs ?? 0}
      />
      <HealthSection monitoring={monitoring} devices={devices} groups={groups} />
      <AlertsSection alerts={alerts} />
    </>
  );
}
