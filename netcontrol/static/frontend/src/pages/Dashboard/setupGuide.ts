import type { TopologySource } from '@/api/meraki';

import { SOURCES_LINK, classifySourceHealth, isTrackedSource } from './sourceHealth';

// First-run guidance for the Dashboard: the setup checklist (which steps this
// user sees and which are done) and which panels are left out because what
// they need is not set up. Pure, so it is unit tested; useSetupGuide gathers
// the queries and the components only render the result.

/** PageHelp-style dismissal key of the setup guide card (lib/helpDismissed). */
export const SETUP_GUIDE_KEY = 'dashboard.setup';

// Deep links into the page and dialog where each step is done. Each target
// page reads its parameter and drops it once the dialog closes.
export const SETUP_LINKS = {
  sources: SOURCES_LINK,
  discovery: '/inventory?open=discovery',
  snmpProfiles: '/inventory?open=snmp-profiles',
  monitoring: '/settings/monitoring',
  backupPolicy: '/configuration/backups?add=policy',
  notifications: '/settings/notifications',
  netflow: '/settings/netflow',
} as const;

/**
 * What the guide knows. A count or list is undefined when it is unknown: the
 * user may not read it, or its request failed. Unknown steps are left out.
 */
export interface SetupInputs {
  isAdmin: boolean;
  /** Features the user has (canUseFeature), keyed by what the guide needs them for. */
  can: { topology: boolean; inventory: boolean; configBackups: boolean; trafficAnalysis: boolean };
  /** GET /api/topology/sources. */
  sources?: readonly TopologySource[];
  /** stats.total_hosts of GET /api/dashboard. */
  totalHosts?: number;
  /** device_health of GET /api/dashboard: devices with an SNMP poll. */
  polledDevices?: number;
  /** GET /api/admin/snmp-profiles. */
  snmpProfiles?: number;
  /** GET /api/config-backups/summary. */
  backupPolicies?: number;
  backups?: number;
  /** GET /api/admin/notification-channels. */
  notificationChannels?: number;
  /** GET /api/flows/status. */
  flowCollectorEnabled?: boolean;
}

export type SetupStepKey = 'source' | 'collection' | 'devices' | 'polling' | 'backups' | 'notifications';

export interface SetupLink {
  to: string;
  label: string;
  /** Opens the app-wide Add source dialog instead of following `to`, when the user may add one. */
  addSource?: boolean;
}

export interface SetupStep {
  key: SetupStepKey;
  title: string;
  /** One line: why it matters. */
  why: string;
  done: boolean;
  action: SetupLink;
}

/**
 * Sources an administrator connects: Meraki, Cato, FMC, Panorama, Appgate
 * and cloud accounts. Neighbor discovery and inventory collection are always
 * listed, so they are not a sign that anything was connected.
 */
export function isConnectedSource(s: TopologySource): boolean {
  return isTrackedSource(s) && s.type !== 'neighbors' && s.type !== 'inventory';
}

/** A connected source whose last collection got something (partial counts). */
export function hasCollected(s: TopologySource, now: number = Date.now()): boolean {
  if (!isConnectedSource(s)) return false;
  const health = classifySourceHealth(s, now);
  return health !== 'never' && health !== 'failed';
}

/**
 * The checklist for this user, in order. A step is left out when the user
 * cannot act on it (adding a source, an SNMP profile or a notification
 * channel is admin-only) or its state is unknown.
 */
export function buildSetupSteps(inp: SetupInputs, now: number = Date.now()): SetupStep[] {
  const steps: SetupStep[] = [];
  const { isAdmin, can } = inp;

  if (isAdmin && can.topology && inp.sources) {
    const sources = inp.sources;
    steps.push({
      key: 'source',
      title: 'Connect a source',
      why: 'Meraki, Cato, firewall managers and cloud accounts draw your sites, links and clouds on the topology map.',
      done: sources.some(isConnectedSource),
      action: { to: SETUP_LINKS.sources, label: 'Add a source', addSource: true },
    });
    steps.push({
      key: 'collection',
      title: 'Collect from it',
      why: 'Nothing shows on the map or in availability until a source has been collected once.',
      done: sources.some((s) => hasCollected(s, now)),
      action: { to: SETUP_LINKS.sources, label: 'Open sources' },
    });
  }

  if (can.inventory && inp.totalHosts !== undefined) {
    steps.push({
      key: 'devices',
      title: 'Add or discover devices',
      why: 'Inventory devices are what Plexus polls, backs up and runs jobs against.',
      done: inp.totalHosts > 0,
      action: { to: SETUP_LINKS.discovery, label: 'Discover devices' },
    });
  }

  if (isAdmin && can.inventory && inp.polledDevices !== undefined) {
    // With no profile the first thing to do is create one; with one, assign
    // it to a group and switch polling on.
    const noProfile = inp.snmpProfiles === undefined || inp.snmpProfiles === 0;
    steps.push({
      key: 'polling',
      title: 'Poll devices with SNMP',
      why: noProfile
        ? 'An SNMP profile holds the credentials for health, interface and response-time polling.'
        : 'Assign an SNMP profile to an inventory group and turn on polling to fill the health charts.',
      done: inp.polledDevices > 0,
      action: noProfile
        ? { to: SETUP_LINKS.snmpProfiles, label: 'Create an SNMP profile' }
        : { to: SETUP_LINKS.monitoring, label: 'Polling settings' },
    });
  }

  if (can.configBackups && inp.backupPolicies !== undefined) {
    steps.push({
      key: 'backups',
      title: 'Create a backup policy',
      why: 'Scheduled configuration backups let you diff and restore a device after a bad change.',
      done: inp.backupPolicies > 0,
      action: { to: SETUP_LINKS.backupPolicy, label: 'New backup policy' },
    });
  }

  if (isAdmin && inp.notificationChannels !== undefined) {
    steps.push({
      key: 'notifications',
      title: 'Add a notification channel',
      why: 'Alerts reach email, Teams, PagerDuty or a webhook only through a channel.',
      done: inp.notificationChannels > 0,
      action: { to: SETUP_LINKS.notifications, label: 'Add a channel' },
    });
  }

  return steps;
}

export interface SetupProgress {
  done: number;
  total: number;
  /** Every step shown is done (or none is shown): the guide has nothing to say. */
  complete: boolean;
}

export function setupProgress(steps: readonly SetupStep[]): SetupProgress {
  const done = steps.filter((s) => s.done).length;
  return { done, total: steps.length, complete: done === steps.length };
}

// ── Panels ──────────────────────────────────────────────────────────────────

export type PanelKey =
  | 'overview'
  | 'groups'
  | 'response'
  | 'bandwidth'
  | 'talkers'
  | 'devices'
  | 'backups'
  | 'health';

/**
 * - `shown`: set up (an empty range keeps the panel's own empty message).
 * - `hidden`: not set up; listed in the Not set up yet card instead.
 * - `pending`: its prerequisite is still loading; a skeleton stands in.
 * - `absent`: the user does not have the feature it reads; not rendered.
 */
export type PanelVisibility = 'shown' | 'hidden' | 'pending' | 'absent';

export const PANEL_TITLES: Record<PanelKey, string> = {
  overview: 'Overall Health',
  groups: 'Group Health',
  response: 'Average Response Time',
  bandwidth: 'Busiest Interfaces',
  talkers: 'Top Talkers',
  devices: 'Devices',
  backups: 'Backup Status',
  health: 'Device Health',
};

/** Panels whose data is the SNMP polls of inventory devices. */
const DEVICE_PANELS = ['overview', 'groups', 'response', 'bandwidth', 'devices', 'health'] as const;

export interface PanelPending {
  flowStatus: boolean;
  backupSummary: boolean;
}

export function panelVisibility(inp: SetupInputs, pending: PanelPending): Record<PanelKey, PanelVisibility> {
  // The device panels read the dashboard response, which is loaded by the
  // time this runs; an unknown count keeps them as they were.
  const devices: PanelVisibility = inp.polledDevices === 0 ? 'hidden' : 'shown';

  const talkers: PanelVisibility = !inp.can.trafficAnalysis
    ? 'absent'
    : inp.flowCollectorEnabled === false
      ? 'hidden'
      : pending.flowStatus
        ? 'pending'
        : 'shown';

  const backups: PanelVisibility = !inp.can.configBackups
    ? 'absent'
    : inp.backupPolicies === 0 && inp.backups === 0
      ? 'hidden'
      : pending.backupSummary
        ? 'pending'
        : 'shown';

  const out = { talkers, backups } as Record<PanelKey, PanelVisibility>;
  for (const key of DEVICE_PANELS) out[key] = devices;
  return out;
}

export interface NotSetUpEntry {
  /** Stable key: the prerequisite. */
  key: 'polling' | 'flows' | 'backups';
  /** The hidden panels, by title, in page order. */
  panels: string[];
  needs: string;
  /** Where to set it up; absent when this user cannot. */
  action?: SetupLink;
}

/** The hidden panels grouped by what they need, with where to set it up. */
export function notSetUpEntries(
  vis: Record<PanelKey, PanelVisibility>,
  inp: SetupInputs,
): NotSetUpEntry[] {
  const out: NotSetUpEntry[] = [];
  const devicePanels = DEVICE_PANELS.filter((k) => vis[k] === 'hidden').map((k) => PANEL_TITLES[k]);
  if (devicePanels.length) {
    const noProfile = inp.snmpProfiles === undefined || inp.snmpProfiles === 0;
    out.push({
      key: 'polling',
      panels: devicePanels,
      needs: 'Inventory devices polled over SNMP.',
      action:
        inp.isAdmin && inp.can.inventory
          ? noProfile
            ? { to: SETUP_LINKS.snmpProfiles, label: 'Create an SNMP profile' }
            : { to: SETUP_LINKS.monitoring, label: 'Polling settings' }
          : undefined,
    });
  }
  if (vis.talkers === 'hidden') {
    out.push({
      key: 'flows',
      panels: [PANEL_TITLES.talkers],
      needs: 'The NetFlow / sFlow collector switched on.',
      action: inp.isAdmin ? { to: SETUP_LINKS.netflow, label: 'Collector settings' } : undefined,
    });
  }
  if (vis.backups === 'hidden') {
    out.push({
      key: 'backups',
      panels: [PANEL_TITLES.backups],
      needs: 'A configuration backup policy.',
      action: { to: SETUP_LINKS.backupPolicy, label: 'New backup policy' },
    });
  }
  return out;
}
