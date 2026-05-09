import { useEffect, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';

import { useAuthStatus } from '@/api/auth';
import { resetSessionExpiryFlag, setSessionExpiredHandler } from '@/api/client';
import { AnimatedBackground } from '@/components/AnimatedBackground';
import { ChangePasswordModal } from '@/components/ChangePasswordModal';
import { Sidebar } from '@/components/Sidebar';
import { UserMenu } from '@/components/UserMenu';
import { Login } from '@/pages/Login/Login';
import { Compliance } from '@/pages/Compliance/Compliance';
import { Configuration } from '@/pages/Configuration/Configuration';
import { CustomDashboards } from '@/pages/Dashboard/CustomDashboards';
import { Dashboard } from '@/pages/Dashboard/Dashboard';
import { DashboardViewer } from '@/pages/Dashboard/DashboardViewer';
import { Deployments } from '@/pages/Deployments/Deployments';
import { DeviceDetail } from '@/pages/DeviceDetail/DeviceDetail';
import { DevicePicker } from '@/pages/DeviceDetail/DevicePicker';
import { Federation } from '@/pages/Federation/Federation';
import { FloorPlan } from '@/pages/FloorPlan/FloorPlan';
import { GraphTemplates } from '@/pages/GraphTemplates/GraphTemplates';
import { ChangeManagement } from '@/pages/ChangeManagement/ChangeManagement';
import { CloudVisibility } from '@/pages/CloudVisibility/CloudVisibility';
import { Inventory } from '@/pages/Inventory/Inventory';
import { Ipam } from '@/pages/Ipam/Ipam';
import { Jobs } from '@/pages/Jobs/Jobs';
import { Lab } from '@/pages/Lab';
import { Monitoring } from '@/pages/Monitoring/Monitoring';
import { MacTracking } from '@/pages/NetworkTools/MacTracking';
import { TrafficAnalysis } from '@/pages/NetworkTools/TrafficAnalysis';
import { Reports } from '@/pages/Reports/Reports';
import { RiskAnalysis } from '@/pages/RiskAnalysis/RiskAnalysis';
import { Settings } from '@/pages/Settings/Settings';
import { Topology } from '@/pages/Topology/Topology';
import { Upgrades } from '@/pages/Upgrades/Upgrades';

const BREADCRUMBS: Record<string, string> = {
  '/': 'Dashboard',
  '/dashboards': 'Dashboards',
  '/devices': 'Devices',
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
  '/upgrades': 'Upgrades',
  '/reports': 'Reports',
  '/graph-templates': 'Graph Templates',
  '/jobs': 'Jobs',
  '/playbooks': 'Playbooks',
  '/templates': 'Templates',
  '/credentials': 'Credentials',
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

export function App() {
  const qc = useQueryClient();
  const { data: auth, isLoading } = useAuthStatus();
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
  // for reasons other than session expiry — the latch resets, the next poll
  // re-trips it, and we churn forever.
  const wasAuthedRef = useRef(false);
  useEffect(() => {
    const isAuthed = !!auth?.authenticated;
    if (isAuthed && !wasAuthedRef.current) resetSessionExpiryFlag();
    wasAuthedRef.current = isAuthed;
  }, [auth?.authenticated]);

  // While the initial auth check is in flight, render nothing — the bundled
  // styles already paint the space-depth background, and a flash-of-login is
  // worse than a blank moment for an authenticated reload.
  if (isLoading) {
    return (
      <div className="app-container">
        <AnimatedBackground />
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
      <AnimatedBackground />

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
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/dashboards" element={<CustomDashboards />} />
          <Route path="/dashboards/:id" element={<DashboardViewer />} />
          <Route path="/devices" element={<DevicePicker />} />
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
          <Route path="/upgrades" element={<Upgrades />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/graph-templates" element={<GraphTemplates />} />
          <Route path="/jobs" element={<Jobs />} />
          <Route path="/playbooks" element={<Jobs />} />
          <Route path="/templates" element={<Jobs />} />
          <Route path="/credentials" element={<Jobs />} />
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
      </main>

      <UserMenu isOpen={userMenuOpen} onClose={() => setUserMenuOpen(false)} />
      <ChangePasswordModal
        isOpen={mustChangePassword}
        forced
        onClose={() => {}}
        onSuccess={() => qc.invalidateQueries({ queryKey: ['auth', 'status'] })}
      />
    </div>
  );
}
