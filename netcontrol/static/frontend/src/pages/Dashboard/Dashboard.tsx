import { Suspense, lazy } from 'react';

import { useAuthStatus } from '@/api/auth';
import { useDashboard } from '@/api/dashboard';
import { useTopologySources } from '@/api/meraki';
import { canUseFeature } from '@/lib/tabGating';
import { useScrollToHash } from '@/lib/useScrollToHash';

import { PageHeader } from '@/components/PageHeader';
import { PageHelp } from '@/components/PageHelp';
import { AlertsSection } from './AlertsSection';
import { CriticalIssuesBanner } from './CriticalIssuesBanner';
import { dashboardLinkAccess } from './dashboardLinks';
import { ISSUE_ANCHORS, PANEL_BODY_HEIGHT, PANEL_CHROME_HEIGHT, RESPONSE_SUMMARY_HEIGHT } from './helpers';
import { DevicesGridPanel } from './DevicesGridPanel';
import { GroupHealthPanel } from './GroupHealthPanel';
import { HealthSection } from './HealthSection';
import { DashboardSwitcher } from './DashboardSwitcher';
import { StatRings } from './StatRings';
import { summarizeSources } from './sourceHealth';

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

// Stands in for a whole chart card while its chunk loads, at the card's own
// height so the page does not shift when the panel appears.
const CHART_CARD_HEIGHT = PANEL_BODY_HEIGHT + PANEL_CHROME_HEIGHT;

function PanelSkeleton({ height = CHART_CARD_HEIGHT }: { height?: number }) {
  return <div className="skeleton skeleton-card" style={{ height }} />;
}

export function Dashboard() {
  const { data, isPending, error } = useDashboard();
  // Topology sources are behind the topology feature: users without it never
  // request them, and the banner and ring just leave them out.
  const { data: auth } = useAuthStatus();
  const canTopology = canUseFeature('topology', auth);
  const sourcesQuery = useTopologySources(canTopology);
  const sources = canTopology ? (sourcesQuery.data?.sources ?? []) : [];
  // Count links (dashboardLinks.ts) open a panel of this page by its anchor.
  useScrollToHash(!isPending, 'smooth');

  if (isPending) {
    return (
      <>
        <PageHeader title="Dashboard" />
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
        <PageHeader title="Dashboard" />
        <div className="glass-card card" style={{ borderColor: 'var(--danger)' }}>
          <strong>Failed to load dashboard:</strong> {(error as Error).message}
        </div>
      </>
    );
  }

  const stats = data?.stats ?? {};
  const groups = data?.groups ?? [];
  const devices = data?.device_health ?? [];
  const alerts = data?.open_alerts ?? [];
  // Absent for users without the monitoring feature.
  const topology = data?.topology;

  return (
    <>
      <PageHeader title="Dashboard">
        <DashboardSwitcher current={null} />
      </PageHeader>
      <PageHelp
        pageKey="dashboard"
        title="Your Network at a Glance"
        text="View device status, recent alerts, backup summaries, and quick stats. The Needs attention banner gathers unreachable or critical devices, interfaces down, failed backups, critical alerts, down or degraded sites, uplinks, tunnels and cloud connections reported by the integrations, and topology sources whose last collection failed, was partial, is overdue or has warnings. Use the dashboard switcher above to open or manage custom dashboards with your own metric panels."
      />
      <div className="stack">
        <CriticalIssuesBanner devices={devices} alerts={alerts} sources={sources} topology={topology} />
        <div className="dashboard-overview-grid">
          <Suspense fallback={<PanelSkeleton />}>
            <OverviewPanels devices={devices} />
          </Suspense>
          <GroupHealthPanel groups={groups} devices={devices} />
        </div>
        <Suspense fallback={<PanelSkeleton height={CHART_CARD_HEIGHT + RESPONSE_SUMMARY_HEIGHT} />}>
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
          sources={canTopology && sourcesQuery.data ? summarizeSources(sources) : undefined}
          entities={topology?.entity_counts}
          access={dashboardLinkAccess(auth)}
        />
        <HealthSection devices={devices} groups={groups} />
        <div id={ISSUE_ANCHORS.alerts}>
          <AlertsSection
            alerts={alerts}
            topologyProblems={topology?.problems}
            topologyProblemCount={topology?.problem_count}
          />
        </div>
      </div>
    </>
  );
}
