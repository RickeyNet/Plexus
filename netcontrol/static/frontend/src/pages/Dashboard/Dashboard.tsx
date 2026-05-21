import { useDashboard } from '@/api/dashboard';

import { PageHelp } from '@/components/PageHelp';
import { AlertsSection } from './AlertsSection';
import { BackupStatusPanel } from './BackupStatusPanel';
import { BandwidthTrendPanel } from './BandwidthTrendPanel';
import { DevicesGridPanel } from './DevicesGridPanel';
import { EventsFeedPanel } from './EventsFeedPanel';
import { GroupHealthPanel } from './GroupHealthPanel';
import { HealthSection } from './HealthSection';
import { OverviewPanels } from './OverviewPanels';
import { ResponseTimePanel } from './ResponseTimePanel';
import { StatRings } from './StatRings';
import { TopTalkersPanel } from './TopTalkersPanel';

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
      <PageHelp
        pageKey="dashboard"
        title="Your Network at a Glance"
        text="View device status, recent alerts, backup summaries, and quick stats. Scroll down to manage custom dashboards with your own metric panels."
      />
      <OverviewPanels devices={devices} />
      <GroupHealthPanel groups={groups} devices={devices} />
      <ResponseTimePanel />
      <BandwidthTrendPanel />
      <TopTalkersPanel />
      <DevicesGridPanel devices={devices} />
      <BackupStatusPanel devices={devices} />
      <EventsFeedPanel />
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
