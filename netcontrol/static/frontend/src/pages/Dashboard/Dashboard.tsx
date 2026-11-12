import { Suspense, lazy, useState } from 'react';

import { useAuthStatus } from '@/api/auth';
import { useDashboard } from '@/api/dashboard';
import { useTopologySources } from '@/api/meraki';
import { isHelpDismissed, setHelpDismissed } from '@/lib/helpDismissed';
import { canUseFeature } from '@/lib/tabGating';
import { useScrollToHash } from '@/lib/useScrollToHash';

import { useAddSource } from '@/components/AddSourceProvider-context';
import { PageHeader } from '@/components/PageHeader';
import { PageHelp } from '@/components/PageHelp';
import { AlertsSection } from './AlertsSection';
import { CriticalIssuesBanner } from './CriticalIssuesBanner';
import { dashboardLinkAccess } from './dashboardLinks';
import { ISSUE_ANCHORS, PANEL_BODY_HEIGHT, PANEL_CHROME_HEIGHT, RESPONSE_SUMMARY_HEIGHT } from './helpers';
import { DevicesGridPanel } from './DevicesGridPanel';
import { GroupHealthPanel } from './GroupHealthPanel';
import { HealthSection } from './HealthSection';
import { IntegrationsSection } from './IntegrationsSection';
import { NotSetUpCard, SetupGuideCard } from './SetupGuideCard';
import { SETUP_GUIDE_KEY, setupProgress } from './setupGuide';
import { DashboardSwitcher } from './DashboardSwitcher';
import { StatRings } from './StatRings';
import { summarizeSources } from './sourceHealth';
import { useSetupGuide } from './useSetupGuide';

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
  const addSource = useAddSource();
  const sourcesQuery = useTopologySources(canTopology);
  const sources = canTopology ? (sourcesQuery.data?.sources ?? []) : [];
  const setup = useSetupGuide(data, sourcesQuery.data?.sources, sourcesQuery.isPending, canTopology);
  // Hidden with the same per-browser flag store as the PageHelp intros.
  const [setupHidden, setSetupHidden] = useState(() => isHelpDismissed(SETUP_GUIDE_KEY));
  // Count links (dashboardLinks.ts) open a panel of this page by its anchor;
  // wait until the panels that depend on the setup state are placed.
  useScrollToHash(!isPending && !Object.values(setup.panels).includes('pending'), 'smooth');
  function showSetupGuide(show: boolean) {
    setHelpDismissed(SETUP_GUIDE_KEY, !show);
    setSetupHidden(!show);
  }

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

  // The checklist waits for every step's state, so it never flashes in and
  // out, and goes away by itself once every step it shows is done.
  const setupOpen = !setup.stepsPending && !setupProgress(setup.steps).complete;
  const panels = setup.panels;
  // Panels that are not set up are not mounted (no requests, no echarts
  // chunk); the device panels share one prerequisite, polled devices.
  const showDevicePanels = panels.overview === 'shown';

  return (
    <>
      <PageHeader title="Dashboard">
        {setupOpen && setupHidden && (
          <button type="button" className="btn btn-sm btn-secondary" onClick={() => showSetupGuide(true)}>
            Setup guide
          </button>
        )}
        {addSource.available && (
          <button
            type="button"
            className="btn btn-sm btn-primary"
            title="Connect Meraki, Cato, a firewall manager or a cloud account"
            onClick={addSource.open}
          >
            Add source
          </button>
        )}
        <DashboardSwitcher current={null} />
      </PageHeader>
      <PageHelp
        pageKey="dashboard"
        title="Your Network at a Glance"
        text="View device status, recent alerts, backup summaries, and quick stats. The Needs attention banner gathers unreachable or critical devices, interfaces down, failed backups, critical alerts, down or degraded sites, uplinks, tunnels and cloud connections reported by the integrations, and topology sources whose last collection failed, was partial, is overdue or has warnings; each row names what is affected and opens the panel or page with the detail, and All clear takes its place when nothing is wrong. A panel with nothing in the selected time range says so and offers the next longer range. Until setup is done, the Get started card lists what to set up next (connect a source, add devices, SNMP polling, a backup policy, a notification channel) with a link to each; hide it and bring it back with Setup guide in the header. Administrators can connect a new source with Add source in the header or the sidebar, from any page. The Integrations section has a card for each connected Meraki, Cato, FMC, Panorama, Appgate, AWS, Azure or GCP source with how its last collection went and how many of its sites, devices, uplinks, tunnels and other links are up, degraded or down, with links to its map and its availability. Every count is a link to exactly what it counted: a health bucket of the donut or a group tile opens the Devices panel or the health table with that filter selected, a backup count lists those hosts, and an integration count opens Monitoring > Availability filtered to its source, type and state. Panels whose data is not set up yet are folded into one Not set up yet card at the bottom. Use the dashboard switcher above to open or manage custom dashboards with your own metric panels."
      />
      <div className="stack">
        <CriticalIssuesBanner devices={devices} alerts={alerts} sources={sources} topology={topology} />
        {setupOpen && !setupHidden && (
          <SetupGuideCard steps={setup.steps} onDismiss={() => showSetupGuide(false)} />
        )}
        {canTopology && (
          <IntegrationsSection
            // A failed request counts as no sources: the section stays out.
            sources={sourcesQuery.isPending ? undefined : (sourcesQuery.data?.sources ?? [])}
            bySource={topology?.by_source}
          />
        )}
        {showDevicePanels && (
          <>
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
          </>
        )}
        {panels.talkers === 'pending' && <PanelSkeleton />}
        {panels.talkers === 'shown' && (
          <Suspense fallback={<PanelSkeleton />}>
            <TopTalkersPanel />
          </Suspense>
        )}
        {showDevicePanels && (
          <div id={ISSUE_ANCHORS.devices}>
            <DevicesGridPanel devices={devices} />
          </div>
        )}
        {panels.backups === 'pending' && <PanelSkeleton />}
        {panels.backups === 'shown' && (
          <div id={ISSUE_ANCHORS.backups}>
            <Suspense fallback={<PanelSkeleton />}>
              <BackupStatusPanel devices={devices} />
            </Suspense>
          </div>
        )}
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
        {showDevicePanels && <HealthSection devices={devices} groups={groups} />}
        <div id={ISSUE_ANCHORS.alerts}>
          <AlertsSection
            alerts={alerts}
            topologyProblems={topology?.problems}
            topologyProblemCount={topology?.problem_count}
          />
        </div>
        {setup.notSetUp.length > 0 && <NotSetUpCard entries={setup.notSetUp} />}
      </div>
    </>
  );
}
