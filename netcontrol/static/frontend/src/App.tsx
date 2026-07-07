import { lazy, Suspense, useEffect, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';

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
const Deployments = lazy(() => pageLoaders.deployments().then(m => ({ default: m.Deployments })));
const DeviceDetail = lazy(() => pageLoaders.deviceDetail().then(m => ({ default: m.DeviceDetail })));
const Federation = lazy(() => pageLoaders.federation().then(m => ({ default: m.Federation })));
const FloorPlan = lazy(() => pageLoaders.floorPlan().then(m => ({ default: m.FloorPlan })));
const GraphTemplates = lazy(() => pageLoaders.graphTemplates().then(m => ({ default: m.GraphTemplates })));
const ChangeManagement = lazy(() => pageLoaders.changeManagement().then(m => ({ default: m.ChangeManagement })));
const CloudVisibility = lazy(() => pageLoaders.cloudVisibility().then(m => ({ default: m.CloudVisibility })));
const Inventory = lazy(() => pageLoaders.inventory().then(m => ({ default: m.Inventory })));
const Ipam = lazy(() => pageLoaders.ipam().then(m => ({ default: m.Ipam })));
const Jobs = lazy(() => pageLoaders.jobs().then(m => ({ default: m.Jobs })));
const Lab = lazy(() => pageLoaders.lab().then(m => ({ default: m.Lab })));
const MaintenanceWindows = lazy(() => pageLoaders.maintenanceWindows().then(m => ({ default: m.MaintenanceWindows })));
const Monitoring = lazy(() => pageLoaders.monitoring().then(m => ({ default: m.Monitoring })));
const MacTracking = lazy(() => pageLoaders.macTracking().then(m => ({ default: m.MacTracking })));
const TrafficAnalysis = lazy(() => pageLoaders.trafficAnalysis().then(m => ({ default: m.TrafficAnalysis })));
const Audit = lazy(() => pageLoaders.audit().then(m => ({ default: m.Audit })));
const Reports = lazy(() => pageLoaders.reports().then(m => ({ default: m.Reports })));
const RiskAnalysis = lazy(() => pageLoaders.riskAnalysis().then(m => ({ default: m.RiskAnalysis })));
const Settings = lazy(() => pageLoaders.settings().then(m => ({ default: m.Settings })));
const Topology = lazy(() => pageLoaders.topology().then(m => ({ default: m.Topology })));

const BREADCRUMBS: Record<string, string> = {
  '/': 'Dashboard',
  '/dashboards': 'Dashboards',
  '/lab': 'Lab / Digital Twin',
  '/mac-tracking': 'MAC Tracking',
  '/traffic-analysis': 'Traffic Analysis',
  '/federation': 'Federation',
  '/floor-plan': 'Floor Plans',
  '/inventory': 'Inventory',
  '/ipam': 'IPAM',
  '/compliance': 'Compliance',
  '/configuration': 'Configuration',
  '/change-management': 'Changes',
  '/risk-analysis': 'Risk Analysis',
  '/deployments': 'Deployments',
  '/maintenance-windows': 'Maintenance Windows',
  '/upgrades': 'Delegator · Upgrades',
  '/reports': 'Reports',
  '/audit': 'Audit',
  '/graph-templates': 'Graph Templates',
  '/assignments': 'Delegator · Assignments',
  '/tasks': 'Delegator · Tasks',
  '/instructions': 'Delegator · Instructions',
  '/credentials': 'Delegator · Credentials',
  '/monitoring': 'Monitoring',
  '/monitoring/alerts': 'Monitoring · Alerts',
  '/monitoring/routes': 'Monitoring · Route Churn',
  '/monitoring/rules': 'Monitoring · Alert Rules',
  '/monitoring/suppressions': 'Monitoring · Suppressions',
  '/monitoring/sla': 'Monitoring · SLA',
  '/monitoring/availability': 'Monitoring · Availability',
  '/monitoring/capacity': 'Monitoring · Capacity',
  '/cloud-visibility': 'Cloud Visibility',
  '/cloud-visibility/topology': 'Cloud · Topology',
  '/cloud-visibility/flow': 'Cloud · Flow Logs',
  '/cloud-visibility/traffic': 'Cloud · Traffic Metrics',
  '/cloud-visibility/policy': 'Cloud · Policy',
  '/topology': 'Topology',
  '/settings': 'Settings',
};

function Breadcrumb() {
  const { pathname } = useLocation();
  let label = BREADCRUMBS[pathname];
  if (!label && pathname.startsWith('/devices/')) label = 'Device Detail';
  if (!label && pathname.startsWith('/dashboards/')) label = 'Dashboard';
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

// Mirrors the legacy app.js METRIC_PAGES list - pages where the global
// time range is meaningful (Dashboard, Monitoring, Device Detail).
function MetricTimeRangeBar() {
  const { pathname } = useLocation();
  const show =
    pathname === '/' ||
    pathname.startsWith('/monitoring') ||
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
          <Route path="/mac-tracking" element={<MacTracking />} />
          <Route path="/traffic-analysis" element={<TrafficAnalysis />} />
          <Route path="/federation" element={<Federation />} />
          <Route path="/floor-plan" element={<FloorPlan />} />
          <Route path="/inventory" element={<Inventory />} />
          <Route path="/ipam" element={<Ipam />} />
          <Route path="/compliance" element={<Compliance />} />
          <Route path="/configuration" element={<Configuration />} />
          <Route path="/change-management" element={<ChangeManagement />} />
          <Route path="/risk-analysis" element={<RiskAnalysis />} />
          <Route path="/deployments" element={<Deployments />} />
          <Route path="/maintenance-windows" element={<MaintenanceWindows />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/audit" element={<Audit />} />
          <Route path="/graph-templates" element={<GraphTemplates />} />
          {/* Delegator: one page renders all five tabs. The legacy paths
              (/jobs, /playbooks, /templates) point at Jobs too so old deep
              links keep working - Jobs.tsx maps them to the right tab. */}
          <Route path="/assignments" element={<Jobs />} />
          <Route path="/tasks" element={<Jobs />} />
          <Route path="/instructions" element={<Jobs />} />
          <Route path="/upgrades" element={<Jobs />} />
          <Route path="/credentials" element={<Jobs />} />
          <Route path="/jobs" element={<Jobs />} />
          <Route path="/playbooks" element={<Jobs />} />
          <Route path="/templates" element={<Jobs />} />
          <Route path="/monitoring" element={<Monitoring />} />
          <Route path="/monitoring/alerts" element={<Monitoring />} />
          <Route path="/monitoring/routes" element={<Monitoring />} />
          <Route path="/monitoring/rules" element={<Monitoring />} />
          <Route path="/monitoring/suppressions" element={<Monitoring />} />
          <Route path="/monitoring/sla" element={<Monitoring />} />
          <Route path="/monitoring/availability" element={<Monitoring />} />
          <Route path="/monitoring/capacity" element={<Monitoring />} />
          <Route path="/cloud-visibility" element={<CloudVisibility />} />
          <Route path="/cloud-visibility/topology" element={<CloudVisibility />} />
          <Route path="/cloud-visibility/flow" element={<CloudVisibility />} />
          <Route path="/cloud-visibility/traffic" element={<CloudVisibility />} />
          <Route path="/cloud-visibility/policy" element={<CloudVisibility />} />
          <Route path="/topology" element={<Topology />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/network-tools" element={<MacTracking />} />
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
