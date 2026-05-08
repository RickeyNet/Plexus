import { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';

import { UpgradesContent } from '@/pages/Upgrades/Upgrades';

import { JobsTab } from './JobsTab';
import { PlaybooksTab } from './PlaybooksTab';
import { TemplatesTab } from './TemplatesTab';
import { CredentialsTab } from './CredentialsTab';

type Tab = 'assignments' | 'tasks' | 'instructions' | 'upgrades' | 'credentials';

const TABS: { key: Tab; label: string; path: string }[] = [
  { key: 'assignments', label: 'Assignments', path: '/assignments' },
  { key: 'tasks', label: 'Tasks', path: '/tasks' },
  { key: 'instructions', label: 'Instructions', path: '/instructions' },
  { key: 'upgrades', label: 'Upgrades', path: '/upgrades' },
  { key: 'credentials', label: 'Credentials', path: '/credentials' },
];

// Legacy → new path map. Keeps any deep links / bookmarks pointing at the
// pre-rename routes working: they resolve to the matching new tab.
const LEGACY_PATHS: Record<string, Tab> = {
  '/jobs': 'assignments',
  '/playbooks': 'tasks',
  '/templates': 'instructions',
};

function tabFromPath(pathname: string): Tab {
  const match = TABS.find((t) => t.path === pathname);
  if (match) return match.key;
  const legacy = LEGACY_PATHS[pathname];
  if (legacy) return legacy;
  return 'assignments';
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
        <h2>Delegator</h2>
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

      {tab === 'assignments' && <JobsTab />}
      {tab === 'tasks' && <PlaybooksTab />}
      {tab === 'instructions' && <TemplatesTab />}
      {tab === 'upgrades' && <UpgradesContent />}
      {tab === 'credentials' && <CredentialsTab />}
    </div>
  );
}
