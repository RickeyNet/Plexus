// Single source of truth for the dynamic import() of every code-split route
// page. App.tsx wraps these in React.lazy; the sidebar calls prefetchRoute()
// on hover/focus to warm the same chunk before the click lands. Because both
// paths call the identical import specifier, Vite emits one chunk and the
// browser dedupes the request - a hovered link is usually already downloaded
// and parsed by the time the user clicks, so navigation feels instant.

type Loader = () => Promise<Record<string, unknown>>;

export const pageLoaders = {
  compliance: () => import('@/pages/Compliance/Compliance'),
  configuration: () => import('@/pages/Configuration/Configuration'),
  customDashboards: () => import('@/pages/Dashboard/CustomDashboards'),
  dashboard: () => import('@/pages/Dashboard/Dashboard'),
  dashboardViewer: () => import('@/pages/Dashboard/DashboardViewer'),
  deviceDetail: () => import('@/pages/DeviceDetail/DeviceDetail'),
  federation: () => import('@/pages/Federation/Federation'),
  floorPlan: () => import('@/pages/FloorPlan/FloorPlan'),
  changeManagement: () => import('@/pages/ChangeManagement/ChangeManagement'),
  cloudVisibility: () => import('@/pages/CloudVisibility/CloudVisibility'),
  inventory: () => import('@/pages/Inventory/Inventory'),
  hardware: () => import('@/pages/Hardware/Hardware'),
  ipam: () => import('@/pages/Ipam/Ipam'),
  routing: () => import('@/pages/Routing/Routing'),
  circuits: () => import('@/pages/Circuits/Circuits'),
  dcim: () => import('@/pages/Dcim/Dcim'),
  sync: () => import('@/pages/Sync/Sync'),
  jobs: () => import('@/pages/Jobs/Jobs'),
  lab: () => import('@/pages/Lab'),
  monitoring: () => import('@/pages/Monitoring/Monitoring'),
  networkTools: () => import('@/pages/NetworkTools/NetworkTools'),
  pluginPage: () => import('@/pages/Plugins/PluginPage'),
  reports: () => import('@/pages/Reports/Reports'),
  settings: () => import('@/pages/Settings/Settings'),
  help: () => import('@/pages/Help/Help'),
  software: () => import('@/pages/Software/Software'),
  topology: () => import('@/pages/Topology/Topology'),
  virtualization: () => import('@/pages/Virtualization/Virtualization'),
  organization: () => import('@/pages/Organization/Organization'),
} satisfies Record<string, Loader>;

type PageKey = keyof typeof pageLoaders;

// Maps the sidebar's static route paths to their page chunk. Dynamic detail
// routes (/devices/:id, /dashboards/:id) are intentionally absent - they have
// no nav link to hover, so there is nothing to prefetch.
const ROUTE_TO_PAGE: Record<string, PageKey> = {
  '/': 'dashboard',
  '/dashboards': 'customDashboards',
  '/inventory': 'inventory',
  '/hardware': 'hardware',
  '/assignments': 'jobs',
  '/tasks': 'jobs',
  '/instructions': 'jobs',
  '/credentials': 'jobs',
  '/topology': 'topology',
  '/ipam': 'ipam',
  '/routing': 'routing',
  '/circuits': 'circuits',
  '/dcim': 'dcim',
  '/sync': 'sync',
  '/software': 'software',
  '/software/upgrades': 'software',
  '/cloud-visibility': 'cloudVisibility',
  '/monitoring': 'monitoring',
  '/configuration': 'configuration',
  '/compliance': 'compliance',
  '/change-management': 'changeManagement',
  '/reports': 'reports',
  '/network-tools': 'networkTools',
  '/network-tools/traffic': 'networkTools',
  '/network-tools/reachability': 'networkTools',
  '/network-tools/summarize': 'networkTools',
  '/federation': 'federation',
  '/floor-plan': 'floorPlan',
  '/lab': 'lab',
  '/settings': 'settings',
  '/help': 'help',
  '/virtualization': 'virtualization',
  '/organization': 'organization',
};

// First path segment to page chunk, for deep links the static table above
// does not list (/monitoring/alerts, /devices/12, /settings/users). Used when
// the app boots on such a URL so its chunk loads alongside the auth check.
const SECTION_TO_PAGE: Record<string, PageKey> = {
  dashboards: 'dashboardViewer',
  devices: 'deviceDetail',
  hardware: 'hardware',
  ipam: 'ipam',
  virtualization: 'virtualization',
  organization: 'organization',
  routing: 'routing',
  circuits: 'circuits',
  dcim: 'dcim',
  sync: 'sync',
  software: 'software',
  compliance: 'compliance',
  configuration: 'configuration',
  'change-management': 'changeManagement',
  reports: 'reports',
  approvals: 'jobs',
  jobs: 'jobs',
  playbooks: 'jobs',
  templates: 'jobs',
  monitoring: 'monitoring',
  'network-tools': 'networkTools',
  'cloud-visibility': 'cloudVisibility',
  settings: 'settings',
  help: 'help',
  plugins: 'pluginPage',
};

function pageForPath(path: string): PageKey | undefined {
  const exact = ROUTE_TO_PAGE[path];
  if (exact) return exact;
  const section = path.split('/')[1];
  return section ? SECTION_TO_PAGE[section] : undefined;
}

// Fire-and-forget warm of a route's chunk. Safe to call repeatedly: the
// underlying import() promise is cached, so extra calls are no-ops. A failed
// warm is ignored; React.lazy runs its own import when the route renders.
export function prefetchRoute(path: string): void {
  const key = pageForPath(path);
  if (key) pageLoaders[key]().catch(() => {});
}
