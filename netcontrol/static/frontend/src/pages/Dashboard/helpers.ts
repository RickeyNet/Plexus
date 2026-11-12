import type { DashboardGroup, DeviceHealth } from '@/api/dashboard';

// Anchor ids the CriticalIssuesBanner rows and the count links
// (dashboardLinks.ts) scroll to. The Dashboard wraps each target panel in a
// div carrying the matching id (the health table carries its own). Kept out
// of the component file so it stays component-only for Vite fast refresh.
export const ISSUE_ANCHORS = {
  devices: 'dashboard-devices',
  backups: 'dashboard-backups',
  alerts: 'dashboard-alerts',
  health: 'network-health-section',
} as const;

/** Group key of the devices that belong to no group. */
export const UNGROUPED_GROUP_KEY = 'ungrouped';

/** The group a device is counted under: its group id, or UNGROUPED_GROUP_KEY. */
export function deviceGroupKey(d: DeviceHealth): string {
  return d.group_id != null ? String(d.group_id) : UNGROUPED_GROUP_KEY;
}

export interface DeviceGroupMembers {
  /** deviceGroupKey of its devices. */
  key: string;
  name: string;
  devices: DeviceHealth[];
}

/**
 * The devices of each group: every group listed (empty ones too, in list
 * order), then the groups only devices name, then Ungrouped. Shared by the
 * Group Health tiles and the health table's group filter, so a tile's link
 * always has a filter option to select.
 */
export function groupDevices(groups: readonly DashboardGroup[], devices: readonly DeviceHealth[]): DeviceGroupMembers[] {
  const byKey = new Map<string, DeviceGroupMembers>();
  for (const g of groups) byKey.set(String(g.id), { key: String(g.id), name: g.name, devices: [] });
  for (const d of devices) {
    const key = deviceGroupKey(d);
    let entry = byKey.get(key);
    if (!entry) {
      const name = key === UNGROUPED_GROUP_KEY ? 'Ungrouped' : d.group_name || `Group ${key}`;
      entry = { key, name, devices: [] };
      byKey.set(key, entry);
    }
    entry.devices.push(d);
  }
  // Ungrouped last, wherever its first device put it.
  const ungrouped = byKey.get(UNGROUPED_GROUP_KEY);
  byKey.delete(UNGROUPED_GROUP_KEY);
  return ungrouped ? [...byKey.values(), ungrouped] : [...byKey.values()];
}

export type HealthStatus = 'healthy' | 'warning' | 'critical' | 'down' | 'unknown';

/** Theme token for each health status (dashboard tiles, rollups, donut). */
export const HEALTH_COLORS: Record<HealthStatus, string> = {
  healthy: 'var(--success)',
  warning: 'var(--warning)',
  critical: 'var(--danger)',
  down: 'var(--danger)',
  unknown: 'var(--text-muted)',
};

/** Display name of each health status, used by every dashboard panel. */
export const HEALTH_LABELS: Record<HealthStatus, string> = {
  healthy: 'Healthy',
  warning: 'Warning',
  critical: 'Critical',
  down: 'Down',
  unknown: 'Unknown',
};

/** Label of the merged critical + down bucket (donut slice, filter chip, group rollup). */
export const CRITICAL_DOWN_LABEL = 'Critical / Down';

/**
 * Height in px of every dashboard panel body: the chart, the loading
 * skeleton, the empty state and the error state, so a panel keeps its size
 * as it loads.
 */
export const PANEL_BODY_HEIGHT = 240;
export const PANEL_BODY_STYLE = { height: PANEL_BODY_HEIGHT } as const;
/** Card padding, border and title row around a panel body. */
export const PANEL_CHROME_HEIGHT = 76;
/** The Avg / Peak row the response-time panel shows above its chart. */
export const RESPONSE_SUMMARY_HEIGHT = 46;

/** Fewest grid rows a custom dashboard panel may span; below this a chart has no room. */
export const MIN_PANEL_ROWS = 2;

export function classifyDeviceHealth(poll: DeviceHealth | undefined | null): HealthStatus {
  if (!poll) return 'unknown';
  if (poll.poll_status === 'error') return 'down';
  const { cpu_percent: cpu, memory_percent: mem, packet_loss_pct: pktLoss } = poll;
  if (
    (cpu != null && cpu >= 90) ||
    (mem != null && mem >= 95) ||
    (pktLoss != null && pktLoss >= 50)
  ) {
    return 'critical';
  }
  if (
    (cpu != null && cpu >= 75) ||
    (mem != null && mem >= 80) ||
    (pktLoss != null && pktLoss >= 10) ||
    (poll.if_down_count ?? 0) > 0
  ) {
    return 'warning';
  }
  if (cpu != null || mem != null) return 'healthy';
  return 'unknown';
}

export type SortBy = 'severity' | 'name' | 'cpu' | 'memory';

/** Worst first: lower sorts earlier. */
export const SEVERITY_ORDER: Record<HealthStatus, number> = {
  down: 0,
  critical: 1,
  warning: 2,
  unknown: 3,
  healthy: 4,
};

/** How many devices fall in each health status. */
export function countDeviceHealth(devices: readonly DeviceHealth[]): Record<HealthStatus, number> {
  const counts: Record<HealthStatus, number> = { healthy: 0, warning: 0, critical: 0, down: 0, unknown: 0 };
  for (const d of devices) counts[classifyDeviceHealth(d)]++;
  return counts;
}

export function sortDevices(devices: DeviceHealth[], sortBy: SortBy): DeviceHealth[] {
  const copy = [...devices];
  switch (sortBy) {
    case 'severity':
      return copy.sort((a, b) => SEVERITY_ORDER[classifyDeviceHealth(a)] - SEVERITY_ORDER[classifyDeviceHealth(b)]);
    case 'name':
      return copy.sort((a, b) => (a.hostname ?? '').localeCompare(b.hostname ?? ''));
    case 'cpu':
      return copy.sort((a, b) => (b.cpu_percent ?? -1) - (a.cpu_percent ?? -1));
    case 'memory':
      return copy.sort((a, b) => (b.memory_percent ?? -1) - (a.memory_percent ?? -1));
    default:
      return copy;
  }
}

export function formatUptime(seconds: number | null | undefined): string {
  if (seconds == null) return '-';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  if (days > 0) return `${days}d ${hours}h`;
  const mins = Math.floor((seconds % 3600) / 60);
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

