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
  deployments: () => import('@/pages/Deployments/Deployments'),
  deviceDetail: () => import('@/pages/DeviceDetail/DeviceDetail'),
  federation: () => import('@/pages/Federation/Federation'),
  floorPlan: () => import('@/pages/FloorPlan/FloorPlan'),
  graphTemplates: () => import('@/pages/GraphTemplates/GraphTemplates'),
  changeManagement: () => import('@/pages/ChangeManagement/ChangeManagement'),
  cloudVisibility: () => import('@/pages/CloudVisibility/CloudVisibility'),
  inventory: () => import('@/pages/Inventory/Inventory'),
  ipam: () => import('@/pages/Ipam/Ipam'),
  jobs: () => import('@/pages/Jobs/Jobs'),
  lab: () => import('@/pages/Lab'),
  maintenanceWindows: () => import('@/pages/MaintenanceWindows/MaintenanceWindows'),
  monitoring: () => import('@/pages/Monitoring/Monitoring'),
  macTracking: () => import('@/pages/NetworkTools/MacTracking'),
  trafficAnalysis: () => import('@/pages/NetworkTools/TrafficAnalysis'),
  audit: () => import('@/pages/Audit/Audit'),
  reports: () => import('@/pages/Reports/Reports'),
  riskAnalysis: () => import('@/pages/RiskAnalysis/RiskAnalysis'),
  settings: () => import('@/pages/Settings/Settings'),
  topology: () => import('@/pages/Topology/Topology'),
} satisfies Record<string, Loader>;

type PageKey = keyof typeof pageLoaders;

// Maps the sidebar's static route paths to their page chunk. Dynamic detail
// routes (/devices/:id, /dashboards/:id) are intentionally absent - they have
// no nav link to hover, so there is nothing to prefetch.
const ROUTE_TO_PAGE: Record<string, PageKey> = {
  '/': 'dashboard',
  '/dashboards': 'customDashboards',
  '/inventory': 'inventory',
  '/assignments': 'jobs',
  '/tasks': 'jobs',
  '/instructions': 'jobs',
  '/upgrades': 'jobs',
  '/credentials': 'jobs',
  '/topology': 'topology',
  '/ipam': 'ipam',
  '/cloud-visibility': 'cloudVisibility',
  '/monitoring': 'monitoring',
  '/configuration': 'configuration',
  '/compliance': 'compliance',
  '/change-management': 'changeManagement',
  '/reports': 'reports',
  '/audit': 'audit',
  '/graph-templates': 'graphTemplates',
  '/mac-tracking': 'macTracking',
  '/traffic-analysis': 'trafficAnalysis',
  '/federation': 'federation',
  '/floor-plan': 'floorPlan',
  '/lab': 'lab',
  '/maintenance-windows': 'maintenanceWindows',
  '/settings': 'settings',
};

// Fire-and-forget warm of a route's chunk. Safe to call repeatedly: the
// underlying import() promise is cached, so extra calls are no-ops.
export function prefetchRoute(path: string): void {
  const key = ROUTE_TO_PAGE[path];
  if (key) void pageLoaders[key]();
}
