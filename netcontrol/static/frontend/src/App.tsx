import { useState } from 'react';
import { Route, Routes, useLocation } from 'react-router-dom';

import { useAuthStatus } from '@/api/auth';
import { AnimatedBackground } from '@/components/AnimatedBackground';
import { Sidebar } from '@/components/Sidebar';
import { UserMenu } from '@/components/UserMenu';
import { Compliance } from '@/pages/Compliance/Compliance';
import { DeviceDetail } from '@/pages/DeviceDetail/DeviceDetail';
import { DevicePicker } from '@/pages/DeviceDetail/DevicePicker';
import { Federation } from '@/pages/Federation/Federation';
import { FloorPlan } from '@/pages/FloorPlan/FloorPlan';
import { Home } from '@/pages/Home';
import { Lab } from '@/pages/Lab';
import { MacTracking } from '@/pages/NetworkTools/MacTracking';
import { TrafficAnalysis } from '@/pages/NetworkTools/TrafficAnalysis';

const BREADCRUMBS: Record<string, string> = {
  '/': 'Dashboard',
  '/devices': 'Devices',
  '/lab': 'Lab / Digital Twin',
  '/mac-tracking': 'MAC Tracking',
  '/traffic-analysis': 'Traffic Analysis',
  '/federation': 'Federation',
  '/floor-plan': 'Floor Plans',
  '/compliance': 'Compliance',
};

function Breadcrumb() {
  const { pathname } = useLocation();
  let label = BREADCRUMBS[pathname];
  if (!label && pathname.startsWith('/devices/')) label = 'Device Detail';
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
  const { data: auth } = useAuthStatus();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);

  const username = auth?.display_name ?? auth?.username ?? 'admin';

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
          <Route path="/" element={<Home />} />
          <Route path="/devices" element={<DevicePicker />} />
          <Route path="/devices/:hostId" element={<DeviceDetail />} />
          <Route path="/lab" element={<Lab />} />
          <Route path="/mac-tracking" element={<MacTracking />} />
          <Route path="/traffic-analysis" element={<TrafficAnalysis />} />
          <Route path="/federation" element={<Federation />} />
          <Route path="/floor-plan" element={<FloorPlan />} />
          <Route path="/compliance" element={<Compliance />} />
          <Route path="/network-tools" element={<MacTracking />} />
        </Routes>
      </main>

      <UserMenu isOpen={userMenuOpen} onClose={() => setUserMenuOpen(false)} />
    </div>
  );
}
