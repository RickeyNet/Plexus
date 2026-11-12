import type { ConfigBackup } from '@/api/configuration';
import type { DashboardAlert, DashboardTopology, DeviceHealth } from '@/api/dashboard';
import type { TopologySource } from '@/api/meraki';

import { rollUpBackups } from './backupRollup';
import { backupsPanelLink, countNoun, devicesPanelLink } from './dashboardLinks';
import { ISSUE_ANCHORS, classifyDeviceHealth } from './helpers';
import {
  SOURCES_LINK,
  describeProblem,
  sourceLabel,
  summarizeSources,
  topologyAvailabilityLink,
} from './sourceHealth';

// What the Dashboard's Needs attention card lists. Pure, so it is tested
// without rendering (criticalIssues.test.ts).

export type IssueSeverity = 'critical' | 'warning';

export interface Issue {
  key: string;
  count: number;
  label: string;
  /** The affected things, one per entry; the card shows the first few. */
  items: string[];
  severity: IssueSeverity;
  /**
   * A Dashboard panel anchor (ISSUE_ANCHORS) to scroll to, or `to` a link:
   * a Dashboard panel with its filter selected (dashboardLinks.ts) or another page.
   */
  target: string | { to: string };
  /** What following the target does, e.g. "Open Sources". */
  action: string;
}

export interface IssueInputs {
  devices: DeviceHealth[];
  alerts: DashboardAlert[];
  /** The latest backup of each host; empty while loading or without the feature. */
  backups: ConfigBackup[];
  /** Topology sources; empty for users without the topology feature. */
  sources: TopologySource[];
  /** Absent for users without the monitoring feature. */
  topology?: DashboardTopology;
}

function hostLabel(d: DeviceHealth): string {
  return d.hostname ?? d.ip_address ?? `Host ${d.host_id ?? '?'}`;
}

function pluralHost(n: number): string {
  return n === 1 ? 'host' : 'hosts';
}

/** Everything currently wrong, critical first, then by count. */
export function buildIssues({ devices, alerts, backups, sources, topology }: IssueInputs): Issue[] {
  const out: Issue[] = [];

  // Unreachable and critically degraded devices.
  const down = devices.filter((d) => classifyDeviceHealth(d) === 'down');
  const critical = devices.filter((d) => classifyDeviceHealth(d) === 'critical');
  if (down.length > 0) {
    out.push({
      key: 'devices-down',
      count: down.length,
      label: down.length === 1 ? 'device unreachable' : 'devices unreachable',
      items: down.map(hostLabel),
      severity: 'critical',
      target: { to: devicesPanelLink('critical') },
      action: 'Show devices',
    });
  }
  if (critical.length > 0) {
    out.push({
      key: 'devices-critical',
      count: critical.length,
      label: critical.length === 1 ? 'device critical' : 'devices critical',
      items: critical.map(hostLabel),
      severity: 'critical',
      target: { to: devicesPanelLink('critical') },
      action: 'Show devices',
    });
  }

  // Interfaces down.
  const withDownIfaces = devices.filter((d) => (d.if_down_count ?? 0) > 0);
  const downIfaceTotal = withDownIfaces.reduce((sum, d) => sum + (d.if_down_count ?? 0), 0);
  if (downIfaceTotal > 0) {
    out.push({
      key: 'interfaces-down',
      count: downIfaceTotal,
      label: `${downIfaceTotal === 1 ? 'interface' : 'interfaces'} down on ${withDownIfaces.length} ${pluralHost(withDownIfaces.length)}`,
      items: withDownIfaces.map((d) => `${hostLabel(d)} (${d.if_down_count})`),
      severity: 'warning',
      target: ISSUE_ANCHORS.devices,
      action: 'Show devices',
    });
  }

  // Failed backups.
  const failed = rollUpBackups(backups, devices).filter((r) => r.state === 'failed');
  if (failed.length > 0) {
    out.push({
      key: 'backups-failed',
      count: failed.length,
      label: failed.length === 1 ? 'backup failed' : 'backups failed',
      items: failed.map((r) => r.hostname),
      severity: 'critical',
      target: { to: backupsPanelLink('failed') },
      action: 'Show backups',
    });
  }

  // Critical alerts.
  const critAlerts = alerts.filter((a) => {
    const sev = (a.severity ?? '').toLowerCase();
    return sev === 'critical' || sev === 'error';
  });
  if (critAlerts.length > 0) {
    out.push({
      key: 'alerts-critical',
      count: critAlerts.length,
      label: critAlerts.length === 1 ? 'critical alert' : 'critical alerts',
      items: critAlerts.map((a) => `${a.hostname ?? '-'}: ${a.message ?? a.metric ?? '-'}`),
      severity: 'critical',
      target: ISSUE_ANCHORS.alerts,
      action: 'Show alerts',
    });
  }

  // Down and degraded integration entities. Most have no inventory host, so
  // they are not among the alerts above. `problems` holds at most 50 of them.
  const counts = topology?.entity_counts;
  const problems = topology?.problems ?? [];
  for (const state of ['down', 'degraded'] as const) {
    const count = counts?.[state] ?? 0;
    if (count === 0) continue;
    out.push({
      key: `topology-${state}`,
      count,
      label: count === 1 ? `integration entity ${state}` : `integration entities ${state}`,
      items: problems.filter((p) => p.state === state).map(describeProblem),
      severity: state === 'down' ? 'critical' : 'warning',
      target: { to: topologyAvailabilityLink(null, { state }) },
      action: 'Open availability',
    });
  }

  // Topology sources.
  const health = summarizeSources(sources);
  const sourceIssues = [
    { key: 'failed', list: health.failed, one: 'source collection failed', many: 'source collections failed', severity: 'critical' },
    { key: 'partial', list: health.partial, one: 'source collected partially', many: 'sources collected partially', severity: 'warning' },
    { key: 'stale', list: health.stale, one: 'source not collected recently', many: 'sources not collected recently', severity: 'warning' },
    { key: 'warnings', list: health.warnings, one: 'source with collection warnings', many: 'sources with collection warnings', severity: 'warning' },
  ] as const;
  for (const { key, list, one, many, severity } of sourceIssues) {
    if (list.length === 0) continue;
    out.push({
      key: `sources-${key}`,
      count: list.length,
      label: list.length === 1 ? one : many,
      items: list.map((s) => (s.message ? `${sourceLabel(s)} - ${s.message}` : sourceLabel(s))),
      severity,
      target: { to: SOURCES_LINK },
      action: 'Open Sources',
    });
  }

  return out.sort((a, b) => {
    if (a.severity !== b.severity) return a.severity === 'critical' ? -1 : 1;
    return b.count - a.count;
  });
}

/** How many of an issue's items the card names before "and N more". */
export const ISSUE_ITEMS_SHOWN = 3;

/** The first few affected things on one line, with how many more there are. */
export function issueSummary(issue: Issue, shown: number = ISSUE_ITEMS_SHOWN): string {
  const names = issue.items.slice(0, shown);
  // `count` is the true total; `items` may be capped or count something else
  // (interfaces by host), so "more" is only said of the items themselves.
  const more = issue.items.length - names.length;
  return more > 0 ? `${names.join(', ')} and ${more} more` : names.join(', ');
}

/**
 * What is being watched, for the all-clear line ("3 devices, 2 sources").
 * Empty when nothing is: an install with nothing set up is not "all clear",
 * and the Get started card speaks for it.
 */
export function watchedSummary({ devices, sources, topology }: Omit<IssueInputs, 'alerts' | 'backups'>): string {
  const parts: string[] = [];
  if (devices.length > 0) parts.push(countNoun(devices.length, 'device', 'devices'));
  // Sources that have collected at least once; one never collected is not watched yet.
  const tracked = summarizeSources(sources).total;
  if (tracked > 0) parts.push(countNoun(tracked, 'source', 'sources'));
  const entities = topology?.entity_counts.total ?? 0;
  if (entities > 0) parts.push(countNoun(entities, 'integration entity', 'integration entities'));
  return parts.join(', ');
}
