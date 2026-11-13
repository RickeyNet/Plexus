// Breadcrumb trail for the shell's top bar. Labels are "Page" or
// "Page · Tab"; a tab crumb links back to its page.

export interface Crumb {
  label: string;
  /** Link target; absent for the current location. */
  to?: string;
}

const LABELS: Record<string, string> = {
  '/dashboards': 'Dashboards',
  '/lab': 'Lab / Digital Twin',
  '/federation': 'Federation',
  '/floor-plan': 'Floor Plans',
  '/inventory': 'Inventory',
  '/ipam': 'IPAM',
  '/software': 'Software · Versions',
  '/software/upgrades': 'Software · Upgrades',
  '/compliance': 'Compliance',
  '/compliance/audit': 'Compliance · CIS Audit',
  '/configuration': 'Configuration',
  '/change-management': 'Changes · Risk Analysis',
  '/change-management/deployments': 'Changes · Deployments',
  '/change-management/maintenance': 'Changes · Maintenance',
  '/reports': 'Reports',
  '/assignments': 'Delegator · Assignments',
  '/tasks': 'Delegator · Tasks',
  '/instructions': 'Delegator · Instructions',
  '/credentials': 'Delegator · Credentials',
  // Legacy paths that still open the Delegator tabs (LEGACY_PATHS in Jobs.tsx).
  '/jobs': 'Delegator · Assignments',
  '/playbooks': 'Delegator · Tasks',
  '/templates': 'Delegator · Instructions',
  '/monitoring': 'Monitoring',
  '/monitoring/alerts': 'Monitoring · Alerts',
  '/monitoring/events': 'Monitoring · Events',
  '/monitoring/sla': 'Monitoring · SLA',
  '/monitoring/availability': 'Monitoring · Availability',
  '/monitoring/capacity': 'Monitoring · Capacity',
  '/monitoring/configure': 'Monitoring · Configure',
  '/cloud-visibility': 'Cloud Visibility',
  '/cloud-visibility/topology': 'Cloud Visibility · Topology',
  '/cloud-visibility/flow': 'Cloud Visibility · Flow Logs',
  '/cloud-visibility/traffic': 'Cloud Visibility · Traffic Metrics',
  '/cloud-visibility/policy': 'Cloud Visibility · Policy',
  '/topology': 'Topology',
  '/topology/reachability': 'Topology · Reachability',
  '/topology/summarize': 'Topology · Summarize',
  '/settings': 'Settings',
  '/network-tools': 'Network Tools · MAC Tracking',
  '/network-tools/traffic': 'Network Tools · Traffic Analysis',
};

// Pages whose tabs are sibling top-level paths rather than /page/<tab>.
const PAGE_HOME: Record<string, string> = {
  Delegator: '/assignments',
};

/**
 * Crumbs after the home link. Empty on the overview dashboard (the home link
 * is the whole trail there) and on unknown paths.
 */
export function breadcrumbTrail(pathname: string): Crumb[] {
  let label = LABELS[pathname];
  if (!label && pathname.startsWith('/devices/')) {
    return [{ label: 'Inventory', to: '/inventory' }, { label: 'Device Detail' }];
  }
  if (!label && pathname.startsWith('/dashboards/')) {
    return [{ label: 'Dashboards', to: '/dashboards' }, { label: 'Dashboard' }];
  }
  // Path-addressed tabs without their own entry (/compliance/results,
  // /settings/users) fall back to their parent's label.
  if (!label) label = LABELS[pathname.slice(0, pathname.lastIndexOf('/'))];
  if (!label) return [];

  const [page, tab] = label.split(' · ');
  if (!tab) return [{ label: page }];
  const home = PAGE_HOME[page] ?? `/${pathname.split('/')[1]}`;
  return [{ label: page, to: home === pathname ? undefined : home }, { label: tab }];
}
