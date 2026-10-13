import { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router';

import { useAuthStatus } from '@/api/auth';
import { PageHelp } from '@/components/PageHelp';
import { TabBar } from '@/components/TabBar';
import { resolveTab, visibleTabs } from '@/lib/tabGating';

import { JobsTab } from './JobsTab';
import { PlaybooksTab } from './PlaybooksTab';
import { TemplatesTab } from './TemplatesTab';
import { CredentialsTab } from './CredentialsTab';

type Tab = 'assignments' | 'tasks' | 'instructions' | 'credentials';

// Each tab gates on the backend feature its API requires, so a user granted
// only some Delegator features never lands on a tab whose data they can't load.
const TABS: { key: Tab; label: string; path: string; feature: string }[] = [
  { key: 'assignments', label: 'Assignments', path: '/assignments', feature: 'jobs' },
  { key: 'tasks', label: 'Tasks', path: '/tasks', feature: 'playbooks' },
  { key: 'instructions', label: 'Instructions', path: '/instructions', feature: 'templates' },
  { key: 'credentials', label: 'Credentials', path: '/credentials', feature: 'credentials' },
];

// Tab-level help. Each tab dismisses independently of the page banner
// via its own pageKey, so hiding the page intro doesn't hide tab help.
const TAB_HELP: Record<Tab, { title: string; text: string }> = {
  assignments: {
    title: 'Run & Track Jobs',
    text: 'Launch tasks against selected devices and watch progress live. Each row is one execution - open it to see streaming logs, per-host status, and the final outcome.',
  },
  tasks: {
    title: 'Reusable Automation Tasks',
    text: 'Python and Ansible scripts that connect to devices and do work - audits, config pushes, remediations. Tasks marked "requires template" need a matching set of Instructions before they can run.',
  },
  instructions: {
    title: 'Configuration Command Sets',
    text: 'Blocks of CLI commands pushed into config mode by a task. Reusable across devices - keep one canonical "access port hardening" or "SNMPv3 user" snippet here and tasks pull it in at run time.',
  },
  credentials: {
    title: 'Credential Management',
    text: 'SSH, SNMP, and API credentials used to connect to devices. Tasks pick a credential at launch time; assign defaults per device on the Inventory page.',
  },
};

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
  const { data: auth } = useAuthStatus();
  const [requestedTab, setTab] = useState<Tab>(() => tabFromPath(pathname));

  const [prevPathname, setPrevPathname] = useState(pathname);
  if (pathname !== prevPathname) {
    setPrevPathname(pathname);
    setTab(tabFromPath(pathname));
  }

  const shownTabs = visibleTabs(TABS, auth);
  const tab = resolveTab(requestedTab, shownTabs);
  const tabPath = TABS.find((x) => x.key === tab)!.path;

  // The sidebar always links to /assignments; send users without `jobs` to
  // the first tab they can open so the URL matches what is rendered.
  useEffect(() => {
    if (auth && tab !== requestedTab) navigate(tabPath, { replace: true });
  }, [auth, tab, requestedTab, tabPath, navigate]);

  function selectTab(t: Tab) {
    const target = TABS.find((x) => x.key === t)!;
    setTab(t);
    if (pathname !== target.path) navigate(target.path);
  }

  const tabHelp = TAB_HELP[tab];

  return (
    <div className="page">
      <div className="page-header">
        <h2>Delegator</h2>
      </div>

      <PageHelp
        pageKey="delegator"
        title="Delegate Work to the Fleet"
        text="Assign automated tasks against your devices - audits, config pushes, remediations - and track them through to completion. Build the inventory of reusable tasks, instructions, and credentials that operators draw from at run time."
      />

      <TabBar
        tabs={shownTabs}
        active={tab}
        onChange={selectTab}
        aria-label="Delegator sections"
      />

      <PageHelp pageKey={`delegator.${tab}`} title={tabHelp.title} text={tabHelp.text} />

      {tab === 'assignments' && <JobsTab />}
      {tab === 'tasks' && <PlaybooksTab />}
      {tab === 'instructions' && <TemplatesTab />}
      {tab === 'credentials' && <CredentialsTab />}
    </div>
  );
}
