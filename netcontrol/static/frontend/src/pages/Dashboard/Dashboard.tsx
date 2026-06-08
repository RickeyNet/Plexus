import { Suspense, lazy } from 'react';

import { useDashboard } from '@/api/dashboard';

import { PageHelp } from '@/components/PageHelp';
import { AlertsSection } from './AlertsSection';
import { CriticalIssuesBanner, ISSUE_ANCHORS } from './CriticalIssuesBanner';
import { DevicesGridPanel } from './DevicesGridPanel';
import { GroupHealthPanel } from './GroupHealthPanel';
import { HealthSection } from './HealthSection';
import { StatRings } from './StatRings';

// Chart panels pull in echarts (~606 KB). Deferring them keeps the home page
// first paint light; each shows a skeleton until its chunk resolves.
const OverviewPanels = lazy(() =>
  import('./OverviewPanels').then((m) => ({ default: m.OverviewPanels })),
);
const BandwidthTrendPanel = lazy(() =>
  import('./BandwidthTrendPanel').then((m) => ({ default: m.BandwidthTrendPanel })),
);
const ResponseTimePanel = lazy(() =>
  import('./ResponseTimePanel').then((m) => ({ default: m.ResponseTimePanel })),
);
const TopTalkersPanel = lazy(() =>
  import('./TopTalkersPanel').then((m) => ({ default: m.TopTalkersPanel })),
);
const BackupStatusPanel = lazy(() =>
  import('./BackupStatusPanel').then((m) => ({ default: m.BackupStatusPanel })),
);
const EventsFeedPanel = lazy(() =>
  import('./EventsFeedPanel').then((m) => ({ default: m.EventsFeedPanel })),
);

const PanelSkeleton = () => <div className="skeleton skeleton-card" />;

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
      <CriticalIssuesBanner devices={devices} alerts={alerts} />
      <Suspense fallback={<PanelSkeleton />}>
        <OverviewPanels devices={devices} />
      </Suspense>
      <GroupHealthPanel groups={groups} devices={devices} />
      <Suspense fallback={<PanelSkeleton />}>
        <ResponseTimePanel />
      </Suspense>
      <Suspense fallback={<PanelSkeleton />}>
        <BandwidthTrendPanel />
      </Suspense>
      <Suspense fallback={<PanelSkeleton />}>
        <TopTalkersPanel />
      </Suspense>
      <div id={ISSUE_ANCHORS.devices}>
        <DevicesGridPanel devices={devices} />
      </div>
      <div id={ISSUE_ANCHORS.backups}>
        <Suspense fallback={<PanelSkeleton />}>
          <BackupStatusPanel devices={devices} />
        </Suspense>
      </div>
      <Suspense fallback={<PanelSkeleton />}>
        <EventsFeedPanel />
      </Suspense>
      <StatRings
        hosts={stats.total_hosts ?? 0}
        playbooks={stats.total_playbooks ?? 0}
        jobs={stats.total_jobs ?? 0}
      />
      <HealthSection monitoring={monitoring} devices={devices} groups={groups} />
      <div id={ISSUE_ANCHORS.alerts}>
        <AlertsSection alerts={alerts} />
      </div>
    </>
  );
}
