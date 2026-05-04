import { Link, Route, Routes } from 'react-router-dom';

import { Compliance } from '@/pages/Compliance/Compliance';
import { DeviceDetail } from '@/pages/DeviceDetail/DeviceDetail';
import { DevicePicker } from '@/pages/DeviceDetail/DevicePicker';
import { Federation } from '@/pages/Federation/Federation';
import { FloorPlan } from '@/pages/FloorPlan/FloorPlan';
import { Home } from '@/pages/Home';
import { Lab } from '@/pages/Lab';
import { MacTracking } from '@/pages/NetworkTools/MacTracking';
import { TrafficAnalysis } from '@/pages/NetworkTools/TrafficAnalysis';

function TopNav() {
  return (
    <nav
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '0.25rem',
        padding: '0.75rem 1.5rem',
        borderBottom: '1px solid var(--border)',
        background: 'var(--bg-secondary)',
      }}
    >
      <strong style={{ marginRight: '1rem', color: 'var(--text)' }}>Plexus</strong>
      <span
        style={{
          fontSize: '0.7rem',
          padding: '0.15rem 0.4rem',
          background: 'var(--primary-dark)',
          color: 'var(--text)',
          borderRadius: '0.25rem',
          textTransform: 'uppercase',
          letterSpacing: '0.05em',
          marginRight: '1rem',
        }}
      >
        Preview
      </span>
      <Link to="/" className="btn btn-sm btn-ghost">
        Home
      </Link>
      <Link to="/devices" className="btn btn-sm btn-ghost">
        Devices
      </Link>
      <Link to="/mac-tracking" className="btn btn-sm btn-ghost">
        MAC Tracking
      </Link>
      <Link to="/traffic-analysis" className="btn btn-sm btn-ghost">
        Traffic Analysis
      </Link>
      <Link to="/lab" className="btn btn-sm btn-ghost">
        Lab / Digital Twin
      </Link>
      <Link to="/federation" className="btn btn-sm btn-ghost">
        Federation
      </Link>
      <Link to="/floor-plan" className="btn btn-sm btn-ghost">
        Floor Plan
      </Link>
      <Link to="/compliance" className="btn btn-sm btn-ghost">
        Compliance
      </Link>
      <a
        href="/"
        className="btn btn-sm btn-ghost"
        style={{ marginLeft: 'auto', color: 'var(--text-muted)' }}
        title="Return to the classic UI"
      >
        ← Classic UI
      </a>
    </nav>
  );
}

export function App() {
  return (
    <div style={{ background: 'var(--bg)', color: 'var(--text)', minHeight: '100vh' }}>
      <TopNav />
      <main style={{ padding: '1.5rem' }}>
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
          {/* Backward compat with the previous /network-tools route. */}
          <Route path="/network-tools" element={<MacTracking />} />
        </Routes>
      </main>
    </div>
  );
}
