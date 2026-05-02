import { Link, Route, Routes } from 'react-router-dom';
import { Page, PageSection } from '@patternfly/react-core';

import { Home } from '@/pages/Home';
import { Lab } from '@/pages/Lab';

function TopNav() {
  const linkStyle: React.CSSProperties = {
    color: 'inherit',
    textDecoration: 'none',
    padding: '8px 16px',
    fontWeight: 500,
  };
  return (
    <nav
      style={{
        display: 'flex',
        gap: 8,
        padding: '12px 24px',
        borderBottom: '1px solid var(--pf-v6-global--BorderColor--100, #ccc)',
        background: 'var(--pf-v6-global--BackgroundColor--100, #fff)',
      }}
    >
      <strong style={{ marginRight: 16 }}>Plexus</strong>
      <Link to="/" style={linkStyle}>
        Home
      </Link>
      <Link to="/lab" style={linkStyle}>
        Lab / Digital Twin
      </Link>
    </nav>
  );
}

export function App() {
  return (
    <Page>
      <TopNav />
      <PageSection>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/lab" element={<Lab />} />
        </Routes>
      </PageSection>
    </Page>
  );
}
