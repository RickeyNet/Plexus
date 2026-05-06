import { useState, type ReactNode } from 'react';
import { NavLink, useLocation } from 'react-router-dom';

import { usePerformanceMode } from '@/lib/usePerformanceMode';

// Navigation mirrors the legacy SPA sidebar (netcontrol/static/index.html). Each
// item is either an internal React route (`to`) or a link back to the legacy UI
// (`href`) when the page hasn't been ported yet. The legacy app lives at /, so
// hrefs use `/#<page>` to land on the correct legacy page hash route.

type Icon = ReactNode;

interface RouteItem {
  label: string;
  icon: Icon;
  to: string;
}

interface LegacyItem {
  label: string;
  icon: Icon;
  href: string;
}

interface NavGroup {
  id: string;
  label: string;
  icon: Icon;
  children: (RouteItem | LegacyItem)[];
}

type TopItem = RouteItem | LegacyItem | NavGroup;

const isGroup = (i: TopItem): i is NavGroup => 'children' in i;
const isRoute = (i: RouteItem | LegacyItem): i is RouteItem => 'to' in i;

const ic = {
  dashboard: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="7" height="7" />
      <rect x="14" y="3" width="7" height="7" />
      <rect x="14" y="14" width="7" height="7" />
      <rect x="3" y="14" width="7" height="7" />
    </svg>
  ),
  inventory: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
      <line x1="8" y1="21" x2="16" y2="21" />
      <line x1="12" y1="17" x2="12" y2="21" />
    </svg>
  ),
  playbooks: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" />
      <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z" />
    </svg>
  ),
  jobs: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
    </svg>
  ),
  templates: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <line x1="16" y1="13" x2="8" y2="13" />
      <line x1="16" y1="17" x2="8" y2="17" />
      <polyline points="10 9 9 9 8 9" />
    </svg>
  ),
  credentials: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  ),
  network: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="5" r="3" />
      <circle cx="5" cy="19" r="3" />
      <circle cx="19" cy="19" r="3" />
      <line x1="12" y1="8" x2="5" y2="16" />
      <line x1="12" y1="8" x2="19" y2="16" />
    </svg>
  ),
  topology: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="6" cy="6" r="3" />
      <circle cx="18" cy="6" r="3" />
      <circle cx="18" cy="18" r="3" />
      <circle cx="6" cy="18" r="3" />
      <line x1="9" y1="6" x2="15" y2="6" />
      <line x1="18" y1="9" x2="18" y2="15" />
      <line x1="9" y1="18" x2="15" y2="18" />
      <line x1="6" y1="9" x2="6" y2="15" />
    </svg>
  ),
  ipam: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 7h18" />
      <path d="M6 3v8" />
      <path d="M18 3v8" />
      <rect x="3" y="11" width="18" height="10" rx="2" />
      <path d="M7 15h4" />
      <path d="M13 15h4" />
      <path d="M7 18h10" />
    </svg>
  ),
  cloud: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17.5 19H9a4 4 0 1 1 .8-7.92A5 5 0 0 1 19 13a3 3 0 0 1-1.5 6z" />
      <path d="M3 19h6" />
    </svg>
  ),
  monitoring: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
    </svg>
  ),
  config: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <path d="M12 18v-6" />
      <path d="M9 15l3 3 3-3" />
    </svg>
  ),
  compliance: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <polyline points="9 12 11 14 15 10" />
    </svg>
  ),
  changes: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2L2 7l10 5 10-5-10-5z" />
      <path d="M2 17l10 5 10-5" />
      <path d="M2 12l10 5 10-5" />
    </svg>
  ),
  reports: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="7 10 12 15 17 10" />
      <line x1="12" y1="15" x2="12" y2="3" />
    </svg>
  ),
  graphs: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 20V10" />
      <path d="M12 20V4" />
      <path d="M6 20v-6" />
    </svg>
  ),
  mac: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
      <line x1="8" y1="21" x2="16" y2="21" />
      <line x1="12" y1="17" x2="12" y2="21" />
    </svg>
  ),
  traffic: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
    </svg>
  ),
  upgrades: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="17 8 12 3 7 8" />
      <line x1="12" y1="3" x2="12" y2="15" />
    </svg>
  ),
  federation: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3" />
      <circle cx="4" cy="6" r="2" />
      <circle cx="20" cy="6" r="2" />
      <circle cx="4" cy="18" r="2" />
      <circle cx="20" cy="18" r="2" />
      <line x1="6" y1="7" x2="10" y2="10" />
      <line x1="14" y1="10" x2="18" y2="7" />
      <line x1="6" y1="17" x2="10" y2="14" />
      <line x1="14" y1="14" x2="18" y2="17" />
    </svg>
  ),
  floorPlan: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z" />
      <circle cx="12" cy="10" r="3" />
    </svg>
  ),
  lab: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 2v6L4 18a2 2 0 0 0 2 3h12a2 2 0 0 0 2-3l-5-10V2" />
      <line x1="9" y1="2" x2="15" y2="2" />
    </svg>
  ),
  settings: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
    </svg>
  ),
  perf: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
    </svg>
  ),
  user: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
      <circle cx="12" cy="7" r="4" />
    </svg>
  ),
  classic: (
    <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="19" y1="12" x2="5" y2="12" />
      <polyline points="12 19 5 12 12 5" />
    </svg>
  ),
  chevron: (
    <svg className="nav-group-chevron nav-label" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="6 9 12 15 18 9" />
    </svg>
  ),
};

const NAV: TopItem[] = [
  { label: 'Dashboard', icon: ic.dashboard, to: '/' },
  { label: 'Inventory', icon: ic.inventory, href: '/#inventory' },
  { label: 'Playbooks', icon: ic.playbooks, href: '/#playbooks' },
  { label: 'Jobs', icon: ic.jobs, href: '/#jobs' },
  { label: 'Templates', icon: ic.templates, href: '/#templates' },
  { label: 'Credentials', icon: ic.credentials, href: '/#credentials' },
  {
    id: 'network',
    label: 'Network',
    icon: ic.network,
    children: [
      { label: 'Topology', icon: ic.topology, href: '/#topology' },
      { label: 'IPAM', icon: ic.ipam, href: '/#ipam' },
      { label: 'Cloud Visibility', icon: ic.cloud, href: '/#cloud-visibility' },
      { label: 'Monitoring', icon: ic.monitoring, href: '/#monitoring' },
      { label: 'Configuration', icon: ic.config, href: '/#configuration' },
      { label: 'Compliance', icon: ic.compliance, to: '/compliance' },
      { label: 'Changes', icon: ic.changes, href: '/#change-management' },
      { label: 'Reports', icon: ic.reports, href: '/#reports' },
      { label: 'Graphs', icon: ic.graphs, href: '/#graph-templates' },
      { label: 'MAC Tracking', icon: ic.mac, to: '/mac-tracking' },
      { label: 'Traffic Analysis', icon: ic.traffic, to: '/traffic-analysis' },
      { label: 'Upgrades', icon: ic.upgrades, href: '/#upgrades' },
      { label: 'Federation', icon: ic.federation, to: '/federation' },
      { label: 'Floor Plans', icon: ic.floorPlan, to: '/floor-plan' },
    ],
  },
  { label: 'Devices', icon: ic.inventory, to: '/devices' },
  { label: 'Lab / Digital Twin', icon: ic.lab, to: '/lab' },
  { label: 'Settings', icon: ic.settings, to: '/settings' },
];

function NavItem({ item, child }: { item: RouteItem | LegacyItem; child?: boolean }) {
  const cls = child ? 'nav-link nav-child-link' : 'nav-link';
  if (isRoute(item)) {
    return (
      <NavLink to={item.to} end={item.to === '/'} className={({ isActive }) => (isActive ? `${cls} active` : cls)}>
        {item.icon}
        <span className="nav-label">{item.label}</span>
      </NavLink>
    );
  }
  return (
    <a href={item.href} className={cls} title="Open in classic UI">
      {item.icon}
      <span className="nav-label">{item.label}</span>
    </a>
  );
}

function NavGroupItem({ group, currentPath }: { group: NavGroup; currentPath: string }) {
  const hasActiveChild = group.children.some(
    (c) => isRoute(c) && (c.to === currentPath || (c.to !== '/' && currentPath.startsWith(c.to))),
  );
  const [expanded, setExpanded] = useState(hasActiveChild);
  return (
    <div className={`nav-group${expanded ? ' expanded' : ''}`}>
      <a
        href="#"
        className={`nav-link nav-group-toggle${hasActiveChild ? ' has-active-child' : ''}`}
        aria-expanded={expanded}
        onClick={(e) => {
          e.preventDefault();
          setExpanded((v) => !v);
        }}
      >
        {group.icon}
        <span className="nav-label">{group.label}</span>
        {ic.chevron}
      </a>
      <div className="nav-group-children">
        <div className="nav-group-children-inner">
          {group.children.map((c) => (
            <NavItem key={c.label} item={c} child />
          ))}
        </div>
      </div>
    </div>
  );
}

interface SidebarProps {
  username: string;
  mobileOpen: boolean;
  onMobileClose: () => void;
  onOpenUserMenu: () => void;
}

export function Sidebar({ username, mobileOpen, onMobileClose, onOpenUserMenu }: SidebarProps) {
  const [collapsed, setCollapsed] = useState(false);
  const { pathname } = useLocation();
  const { enabled: perfEnabled, toggle: togglePerf } = usePerformanceMode();

  const navClass = [
    'sidebar',
    collapsed ? 'collapsed' : '',
    mobileOpen ? 'mobile-open' : '',
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <nav className={navClass} aria-label="Main navigation" onClick={() => mobileOpen && onMobileClose()}>

      <div className="sidebar-top">
        <div className="nav-brand">
          <div className="nav-orb" aria-hidden="true" />
          <span className="nav-brand-text">Plexus</span>
        </div>
        <button
          className="sidebar-toggle"
          onClick={() => setCollapsed((v) => !v)}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          aria-expanded={!collapsed}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="15 18 9 12 15 6" />
          </svg>
        </button>
      </div>
      <div className="nav-links">
        {NAV.map((item) =>
          isGroup(item) ? (
            <NavGroupItem key={item.id} group={item} currentPath={pathname} />
          ) : (
            <NavItem key={item.label} item={item} />
          ),
        )}
      </div>
      <div className="sidebar-bottom">
        <a
          href="#"
          className={`nav-link perf-toggle${perfEnabled ? ' active' : ''}`}
          title={perfEnabled ? 'Performance Mode ON — click to disable' : 'Performance Mode — reduce animations and blur'}
          onClick={(e) => {
            e.preventDefault();
            togglePerf();
          }}
        >
          {ic.perf}
          <span className="nav-label">Performance</span>
        </a>
        <a
          href="#"
          className="nav-link nav-user"
          onClick={(e) => {
            e.preventDefault();
            onOpenUserMenu();
          }}
        >
          {ic.user}
          <span className="nav-label nav-user-label">{username}</span>
        </a>
        <a
          href="/"
          className="nav-link"
          title="Return to the classic UI"
          style={{ color: 'var(--text-muted)' }}
        >
          {ic.classic}
          <span className="nav-label">Classic UI</span>
        </a>
      </div>
    </nav>
  );
}
