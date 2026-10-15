import { lazy, Suspense, useEffect, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Navigate, Route, Routes, useLocation } from 'react-router';

import { useAuthStatus } from '@/api/auth';
import { resetSessionExpiryFlag, setSessionExpiredHandler } from '@/api/client';
import { ChangePasswordModal } from '@/components/ChangePasswordModal';
import { ErrorBoundary } from '@/components/ErrorBoundary';
import { PageLoader } from '@/components/PageLoader';
import { StarfieldCanvas } from '@/components/StarfieldCanvas';
import { IdleTimeoutWatcher } from '@/components/IdleTimeoutWatcher';
import { Sidebar } from '@/components/Sidebar';
import { TimeRangeBar } from '@/components/TimeRangeBar';
import { UserMenu } from '@/components/UserMenu';
import { pageLoaders } from '@/lib/pageLoaders';
import { Login } from '@/pages/Login/Login';

// Route-level code splitting: each page becomes its own chunk so the initial
// bundle no longer pulls in vis-network (Topology), echarts (Dashboard tiles),
// and codemirror (Jobs/Configuration editors) up front. The import() thunks
// live in pageLoaders so the sidebar can prefetch the exact same chunk on
// hover; here we just reshape each named export into { default } for lazy().
const Compliance = lazy(() => pageLoaders.compliance().then(m => ({ default: m.Compliance })));
const Configuration = lazy(() => pageLoaders.configuration().then(m => ({ default: m.Configuration })));
const CustomDashboards = lazy(() => pageLoaders.customDashboards().then(m => ({ default: m.CustomDashboards })));
const Dashboard = lazy(() => pageLoaders.dashboard().then(m => ({ default: m.Dashboard })));
const DashboardViewer = lazy(() => pageLoaders.dashboardViewer().then(m => ({ default: m.DashboardViewer })));
const DeviceDetail = lazy(() => pageLoaders.deviceDetail().then(m => ({ default: m.DeviceDetail })));
const Federation = lazy(() => pageLoaders.federation().then(m => ({ default: m.Federation })));
const FloorPlan = lazy(() => pageLoaders.floorPlan().then(m => ({ default: m.FloorPlan })));
const ChangeManagement = lazy(() => pageLoaders.changeManagement().then(m => ({ default: m.ChangeManagement })));
const CloudVisibility = lazy(() => pageLoaders.cloudVisibility().then(m => ({ default: m.CloudVisibility })));
const Inventory = lazy(() => pageLoaders.inventory().then(m => ({ default: m.Inventory })));
const Ipam = lazy(() => pageLoaders.ipam().then(m => ({ default: m.Ipam })));
const Software = lazy(() => pageLoaders.software().then(m => ({ default: m.Software })));
const Jobs = lazy(() => pageLoaders.jobs().then(m => ({ default: m.Jobs })));
const Lab = lazy(() => pageLoaders.lab().then(m => ({ default: m.Lab })));
const Monitoring = lazy(() => pageLoaders.monitoring().then(m => ({ default: m.Monitoring })));
const NetworkTools = lazy(() => pageLoaders.networkTools().then(m => ({ default: m.NetworkTools })));
const Reports = lazy(() => pageLoaders.reports().then(m => ({ default: m.Reports })));
const Settings = lazy(() => pageLoaders.settings().then(m => ({ default: m.Settings })));
const Topology = lazy(() => pageLoaders.topology().then(m => ({ default: m.TopologyPage })));

const BREADCRUMBS: Record<string, string> = {
  '/': 'Dashboard',
  '/dashboards': 'Dashboards',
  '/lab': 'Lab / Digital Twin',
  '/federation': 'Federation',
  '/floor-plan': 'Floor Plans',
  '/inventory': 'Inventory',
  '/ipam': 'IPAM',
  '/software': 'Software · Versions',
  '/software/upgrades': 'Software · Upgrades',
  '/compliance': 'Compliance',
  '/compliance/audit': 'Compliance · CIS Audit',
  '/configuration': 'Configuration',
  '/change-management': 'Changes',
  '/change-management/deployments': 'Changes · Deployments',
  '/change-management/maintenance': 'Changes · Maintenance',
  '/reports': 'Reports',
  '/assignments': 'Delegator · Assignments',
  '/tasks': 'Delegator · Tasks',
  '/instructions': 'Delegator · Instructions',
  '/credentials': 'Delegator · Credentials',
  '/monitoring': 'Monitoring',
  '/monitoring/alerts': 'Monitoring · Alerts',
  '/monitoring/events': 'Monitoring · Events',
  '/monitoring/sla': 'Monitoring · SLA',
  '/monitoring/availability': 'Monitoring · Availability',
  '/monitoring/capacity': 'Monitoring · Capacity',
  '/monitoring/configure': 'Monitoring · Configure',
  '/cloud-visibility': 'Cloud Visibility',
  '/cloud-visibility/topology': 'Cloud · Topology',
  '/cloud-visibility/flow': 'Cloud · Flow Logs',
  '/cloud-visibility/traffic': 'Cloud · Traffic Metrics',
  '/cloud-visibility/policy': 'Cloud · Policy',
  '/topology': 'Topology',
  '/topology/reachability': 'Topology · Reachability',
  '/settings': 'Settings',
  '/network-tools': 'Network Tools · MAC Tracking',
  '/network-tools/traffic': 'Network Tools · Traffic Analysis',
};

function Breadcrumb() {
  const { pathname } = useLocation();
  let label = BREADCRUMBS[pathname];
  if (!label && pathname.startsWith('/devices/')) label = 'Device Detail';
  if (!label && pathname.startsWith('/dashboards/')) label = 'Dashboard';
  // Path-addressed tabs (/compliance/results, /settings/users) fall back to
  // their page's label.
  if (!label) label = BREADCRUMBS[pathname.slice(0, pathname.lastIndexOf('/'))];
  if (!label) label = 'Plexus';
  return (
    <div className="breadcrumb-bar">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
        <polyline points="9 22 9 12 15 12 15 22" />
      </svg>
      <span>{label}</span>
    </div>
  );
}

// Pages whose queries read useTimeRange(): the overview dashboard, custom
// dashboards and device detail. Monitoring tabs poll on their own schedule
// (Capacity has its own 30-365d history selector), so the bar is not shown
// there.
function MetricTimeRangeBar() {
  const { pathname } = useLocation();
  const show =
    pathname === '/' ||
    pathname.startsWith('/dashboards') ||
    pathname.startsWith('/devices/');
  if (!show) return null;
  return <TimeRangeBar />;
}

export function App() {
  const qc = useQueryClient();
  const { data: auth, isLoading } = useAuthStatus();
  const { pathname } = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);

  // Wire the api-client 401 handler so any expired session bumps the user
  // back to the login screen without a hard navigation away from /frontend/.
  useEffect(() => {
    setSessionExpiredHandler(() => {
      qc.invalidateQueries({ queryKey: ['auth', 'status'] });
    });
    return () => setSessionExpiredHandler(null);
  }, [qc]);

  // Reset the 401 latch only on the unauthenticated→authenticated transition
  // (i.e. fresh login). Resetting on every authenticated render causes a
  // re-render storm when a feature-gated endpoint legitimately returns 401
  // for reasons other than session expiry - the latch resets, the next poll
  // re-trips it, and we churn forever.
  const wasAuthedRef = useRef(false);
  useEffect(() => {
    const isAuthed = !!auth?.authenticated;
    if (isAuthed && !wasAuthedRef.current) resetSessionExpiryFlag();
    wasAuthedRef.current = isAuthed;
  }, [auth?.authenticated]);

  // While the initial auth check is in flight, render nothing - the bundled
  // styles already paint the space-depth background, and a flash-of-login is
  // worse than a blank moment for an authenticated reload.
  if (isLoading) {
    return (
      <div className="app-container">
        <AppBackground />
      </div>
    );
  }

  if (!auth?.authenticated) {
    return <Login />;
  }

  const username = auth.display_name ?? auth.username ?? 'admin';
  const mustChangePassword = !!auth.must_change_password;

  return (
    <div className="app-container">
      <AppBackground />

      <button
        className="hamburger-btn"
        aria-label="Toggle navigation"
        onClick={() => setMobileOpen((v) => !v)}
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <line x1="3" y1="6" x2="21" y2="6" />
          <line x1="3" y1="12" x2="21" y2="12" />
          <line x1="3" y1="18" x2="21" y2="18" />
        </svg>
      </button>
      <div
        className={`sidebar-backdrop${mobileOpen ? ' visible' : ''}`}
        onClick={() => setMobileOpen(false)}
      />

      <Sidebar
        username={username}
        mobileOpen={mobileOpen}
        onMobileClose={() => setMobileOpen(false)}
        onOpenUserMenu={() => setUserMenuOpen(true)}
      />

      <main className="main-content" aria-live="polite">
        <Breadcrumb />
        <MetricTimeRangeBar />
        <ErrorBoundary resetKey={pathname}>
        <Suspense fallback={<PageLoader />}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/dashboards" element={<CustomDashboards />} />
          <Route path="/dashboards/:id" element={<DashboardViewer />} />
          <Route path="/devices/:hostId" element={<DeviceDetail />} />
          <Route path="/lab" element={<Lab />} />
          {/* Network Tools: MAC Tracking (default) and Traffic Analysis tabs.
              Their old standalone paths redirect to the matching tab. */}
          <Route path="/network-tools/:tab?" element={<NetworkTools />} />
          <Route path="/mac-tracking" element={<Navigate to="/network-tools" replace />} />
          <Route path="/traffic-analysis" element={<Navigate to="/network-tools/traffic" replace />} />
          <Route path="/federation" element={<Federation />} />
          <Route path="/floor-plan" element={<FloorPlan />} />
          <Route path="/inventory" element={<Inventory />} />
          <Route path="/ipam" element={<Ipam />} />
          {/* Software: one page renders the Versions and Upgrades tabs.
              /upgrades is the upgrade tool's old path (it was a Delegator
              tab); bookmarks to it are sent to the Upgrades tab. */}
          <Route path="/software/:tab?" element={<Software />} />
          <Route path="/upgrades" element={<Navigate to="/software/upgrades" replace />} />
          {/* Tabbed pages: /page is the default tab, /page/<tab> the others. */}
          <Route path="/compliance/:tab?" element={<Compliance />} />
          <Route path="/configuration/:tab?" element={<Configuration />} />
          <Route path="/change-management/:tab?" element={<ChangeManagement />} />
          <Route path="/reports/:tab?" element={<Reports />} />
          {/* Retired standalone pages, now tabs of the pages above. */}
          <Route path="/audit" element={<Navigate to="/compliance/audit" replace />} />
          <Route path="/risk-analysis" element={<Navigate to="/change-management" replace />} />
          <Route path="/deployments" element={<Navigate to="/change-management/deployments" replace />} />
          <Route path="/maintenance-windows" element={<Navigate to="/change-management/maintenance" replace />} />
          <Route path="/graph-templates" element={<Navigate to="/monitoring/configure/graph-templates" replace />} />
          {/* Delegator: one page renders all four tabs. The legacy paths
              (/jobs, /playbooks, /templates) point at Jobs too so old deep
              links keep working - Jobs.tsx maps them to the right tab. */}
          <Route path="/assignments" element={<Jobs />} />
          <Route path="/tasks" element={<Jobs />} />
          <Route path="/instructions" element={<Jobs />} />
          <Route path="/credentials" element={<Jobs />} />
          <Route path="/jobs" element={<Jobs />} />
          <Route path="/playbooks" element={<Jobs />} />
          <Route path="/templates" element={<Jobs />} />
          {/* Monitoring: /monitoring/<tab>, and /monitoring/configure/<sub>
              for the Configure tab's sub-tabs. */}
          <Route path="/monitoring/:tab?/:sub?" element={<Monitoring />} />
          {/* Route Churn is now a filter on the Alerts tab. */}
          <Route path="/monitoring/routes" element={<Navigate to="/monitoring/alerts" replace />} />
          {/* Configuration tabs that moved under Configure. Alert Rules is
              Configure's default sub-tab, so it lands on /monitoring/configure. */}
          <Route path="/monitoring/rules" element={<Navigate to="/monitoring/configure" replace />} />
          <Route path="/monitoring/suppressions" element={<Navigate to="/monitoring/configure/suppressions" replace />} />
          <Route path="/monitoring/oid-profiles" element={<Navigate to="/monitoring/configure/oid-profiles" replace />} />
          <Route path="/cloud-visibility/:tab?" element={<CloudVisibility />} />
          {/* Topology: the map (/topology) and the reachability sweep (/topology/reachability). */}
          <Route path="/topology/:tab?" element={<Topology />} />
          <Route path="/settings/:tab?" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
        </Suspense>
        </ErrorBoundary>
      </main>

      <UserMenu isOpen={userMenuOpen} onClose={() => setUserMenuOpen(false)} />
      <IdleTimeoutWatcher />
      <ChangePasswordModal
        isOpen={mustChangePassword}
        forced
        onClose={() => {}}
        onSuccess={() => qc.invalidateQueries({ queryKey: ['auth', 'status'] })}
      />
    </div>
  );
}

function AppBackground() {
  return (
    <>
      <div className="animated-bg" aria-hidden="true">
        <div className="space-depth space-depth-app">
          <div className="space-nebula nebula-a" />
          <div className="space-nebula nebula-b" />
          <div className="space-nebula nebula-c" />
          <div className="space-vignette" />
        </div>
      </div>
      <StarfieldCanvas className="app-particles" />
    </>
  );
}
