import { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';

import { PageHelp } from '@/components/PageHelp';
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
  upgrades: {
    title: 'Firmware Upgrade Campaigns',
    text: 'Plan and execute IOS-XE upgrades across the fleet. Stage images, schedule maintenance windows, and run multi-phase campaigns with backups and rollback support.',
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
  const [tab, setTab] = useState<Tab>(() => tabFromPath(pathname));

  const [prevPathname, setPrevPathname] = useState(pathname);
  if (pathname !== prevPathname) {
    setPrevPathname(pathname);
    setTab(tabFromPath(pathname));
  }

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
        text="Assign automated tasks against your devices - audits, config pushes, remediations, firmware upgrades - and track them through to completion. Build the inventory of reusable tasks, instructions, and credentials that operators draw from at run time."
      />

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

      <PageHelp pageKey={`delegator.${tab}`} title={tabHelp.title} text={tabHelp.text} />

      {tab === 'assignments' && <JobsTab />}
      {tab === 'tasks' && <PlaybooksTab />}
      {tab === 'instructions' && <TemplatesTab />}
      {tab === 'upgrades' && <UpgradesContent />}
      {tab === 'credentials' && <CredentialsTab />}
    </div>
  );
}
