import { Link, Route, Routes } from 'react-router-dom';

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
      <Link to="/" className="btn btn-sm btn-ghost">
        Home
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
          <Route path="/lab" element={<Lab />} />
          <Route path="/mac-tracking" element={<MacTracking />} />
          <Route path="/traffic-analysis" element={<TrafficAnalysis />} />
          {/* Backward compat with the previous /network-tools route. */}
          <Route path="/network-tools" element={<MacTracking />} />
        </Routes>
      </main>
    </div>
  );
}
