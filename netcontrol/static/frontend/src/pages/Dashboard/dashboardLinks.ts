import type { AuthStatus } from '@/api/auth';
import type { DeviceHealth } from '@/api/dashboard';
import { canUseFeature } from '@/lib/tabGating';

import type { BackupState } from './backupRollup';
import { CRITICAL_DOWN_LABEL, HEALTH_LABELS, ISSUE_ANCHORS, countDeviceHealth, type HealthStatus } from './helpers';

// Where each count on the Dashboard links to, already filtered to what it
// counted. Most device and backup counts open a Dashboard panel with its
// filter selected (only the Dashboard's own data reproduces those sets);
// the panels read the same parameters back through the parsers below, so
// a link and its destination cannot drift. Integration counts go to
// Monitoring -> Availability (topologyAvailabilityLink in sourceHealth.ts).
// Pure, so it is unit tested (dashboardLinks.test.ts).

/** Devices panel filter (the tile grid): `?devices=<bucket>`. */
export const DEVICES_FILTER_PARAM = 'devices';
/** Health table group filter: `?group=<group key>` (deviceGroupKey). */
export const HEALTH_GROUP_PARAM = 'group';
/** Health table status filter: `?health=<bucket>`. */
export const HEALTH_STATUS_PARAM = 'health';
/** Backup Status panel filter: `?backups=<state>`. */
export const BACKUP_STATE_PARAM = 'backups';

/** A device health bucket the Dashboard filters by; `critical` is critical and down together. */
export type DeviceHealthFilter = 'critical' | 'warning' | 'healthy' | 'unknown';

/** The buckets in the order the panels list them, with their labels. */
export const DEVICE_HEALTH_FILTERS: readonly { key: DeviceHealthFilter; label: string }[] = [
  { key: 'critical', label: CRITICAL_DOWN_LABEL },
  { key: 'warning', label: HEALTH_LABELS.warning },
  { key: 'healthy', label: HEALTH_LABELS.healthy },
  { key: 'unknown', label: HEALTH_LABELS.unknown },
];

/** The bucket a device in `status` is counted under. */
export function deviceHealthFilterOf(status: HealthStatus): DeviceHealthFilter {
  return status === 'down' ? 'critical' : status;
}

/** How many devices fall in each bucket. */
export function countDeviceHealthFilters(devices: readonly DeviceHealth[]): Record<DeviceHealthFilter, number> {
  const c = countDeviceHealth(devices);
  return { critical: c.critical + c.down, warning: c.warning, healthy: c.healthy, unknown: c.unknown };
}

/** Reads a bucket parameter; null when absent or not a bucket. */
export function parseDeviceHealthFilter(value: string | null | undefined): DeviceHealthFilter | null {
  return DEVICE_HEALTH_FILTERS.find((f) => f.key === value)?.key ?? null;
}

export const BACKUP_STATES: readonly BackupState[] = ['success', 'stale', 'failed', 'never'];

/** Reads the `?backups=` value; null when absent or not a backup state. */
export function parseBackupState(value: string | null | undefined): BackupState | null {
  return BACKUP_STATES.find((s) => s === value) ?? null;
}

/** Reads the `?group=` value; null when absent or blank (the table also ignores a group it does not have). */
export function parseGroupKey(value: string | null | undefined): string | null {
  const v = (value ?? '').trim();
  return v && v.length <= 64 ? v : null;
}

function dashboardLink(params: Record<string, string | null | undefined>, anchor: string): string {
  const search = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v) search.set(k, v);
  const query = search.toString();
  return `/${query ? `?${query}` : ''}#${anchor}`;
}

/** The Devices panel, filtered to `filter` (every device when absent). */
export function devicesPanelLink(filter?: DeviceHealthFilter | null): string {
  return dashboardLink({ [DEVICES_FILTER_PARAM]: filter }, ISSUE_ANCHORS.devices);
}

/** The health table, filtered to a group and / or a bucket. */
export function healthTableLink({ group, health }: { group?: string | null; health?: DeviceHealthFilter | null }): string {
  return dashboardLink({ [HEALTH_GROUP_PARAM]: group, [HEALTH_STATUS_PARAM]: health }, ISSUE_ANCHORS.health);
}

/** The Backup Status panel, listing the hosts in `state` (the problem hosts when absent). */
export function backupsPanelLink(state?: BackupState | null): string {
  return dashboardLink({ [BACKUP_STATE_PARAM]: state }, ISSUE_ANCHORS.backups);
}

/** Pages the totals open, unfiltered: what they count is everything there. */
export const INVENTORY_LINK = '/inventory';
export const TASKS_LINK = '/tasks';
export const ASSIGNMENTS_LINK = '/assignments';

/** Which other pages this user may open, so a count never links to one they cannot. */
export interface DashboardLinkAccess {
  inventory: boolean;
  playbooks: boolean;
  jobs: boolean;
  monitoring: boolean;
  topology: boolean;
}

/** Same rules as the sidebar and the page tabs (canUseFeature). */
export function dashboardLinkAccess(auth: AuthStatus | undefined): DashboardLinkAccess {
  return {
    inventory: canUseFeature('inventory', auth),
    playbooks: canUseFeature('playbooks', auth),
    jobs: canUseFeature('jobs', auth),
    monitoring: canUseFeature('monitoring', auth),
    topology: canUseFeature('topology', auth),
  };
}

/** "3 devices", "1 device". */
export function countNoun(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}
