import { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';

import { JobsTab } from './JobsTab';
import { PlaybooksTab } from './PlaybooksTab';
import { TemplatesTab } from './TemplatesTab';
import { CredentialsTab } from './CredentialsTab';

type Tab = 'jobs' | 'playbooks' | 'templates' | 'credentials';

const TABS: { key: Tab; label: string; path: string }[] = [
  { key: 'jobs', label: 'Jobs', path: '/jobs' },
  { key: 'playbooks', label: 'Playbooks', path: '/playbooks' },
  { key: 'templates', label: 'Templates', path: '/templates' },
  { key: 'credentials', label: 'Credentials', path: '/credentials' },
];

function tabFromPath(pathname: string): Tab {
  const match = TABS.find((t) => t.path === pathname);
  return match?.key ?? 'jobs';
}

export function Jobs() {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const [tab, setTab] = useState<Tab>(() => tabFromPath(pathname));

  useEffect(() => {
    setTab(tabFromPath(pathname));
  }, [pathname]);

  function selectTab(t: Tab) {
    const target = TABS.find((x) => x.key === t)!;
    setTab(t);
    if (pathname !== target.path) navigate(target.path);
  }

  return (
    <div className="page">
      <div className="page-header">
        <h2>Automation</h2>
      </div>

      <div role="tablist" style={{ marginBottom: '1rem', display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
        {TABS.map((t) => (
          <button
            key={t.key}
            role="tab"
            aria-selected={tab === t.key}
            className={`btn btn-sm btn-secondary mon-tab-btn${tab === t.key ? ' active' : ''}`}
            onClick={() => selectTab(t.key)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'jobs' && <JobsTab />}
      {tab === 'playbooks' && <PlaybooksTab />}
      {tab === 'templates' && <TemplatesTab />}
      {tab === 'credentials' && <CredentialsTab />}
    </div>
  );
}
