import { describe, expect, it } from 'vitest';

import type { DashboardTopology, DeviceHealth, TopologyProblem } from '@/api/dashboard';
import type { TopologySource } from '@/api/meraki';

import { buildIssues, issueSummary, watchedSummary, type Issue, type IssueInputs } from './criticalIssues';
import { ISSUE_ANCHORS } from './helpers';
import { backupsPanelLink, devicesPanelLink } from './dashboardLinks';
import { SOURCES_LINK, topologyAvailabilityLink } from './sourceHealth';

function source(over: Partial<TopologySource> = {}): TopologySource {
  return {
    key: 'org:1',
    type: 'meraki',
    id: 1,
    name: 'Example Org',
    status: 'success',
    last_collected_at: new Date().toISOString(),
    message: '',
    detail: '',
    warning_count: 0,
    collecting: false,
    can_collect: true,
    enabled: true,
    demo: false,
    ...over,
  } as TopologySource;
}

function problem(over: Partial<TopologyProblem> = {}): TopologyProblem {
  return {
    provider: 'cato',
    provider_label: 'Cato',
    org_ref: 1,
    org_name: 'Example account',
    entity_type: 'tunnel',
    type_label: 'Tunnel',
    entity_id: 't1',
    name: 'Tunnel C',
    site: 'Branch A',
    host_id: null,
    state: 'down',
    raw_status: 'down',
    since: null,
    ...over,
  } as TopologyProblem;
}

function topology(over: Partial<DashboardTopology> = {}): DashboardTopology {
  return {
    entity_counts: { up: 0, degraded: 0, down: 0, unknown: 0, total: 0 },
    by_provider: {},
    problem_count: 0,
    problems: [],
    ...over,
  } as DashboardTopology;
}

function inputs(over: Partial<IssueInputs> = {}): IssueInputs {
  return { devices: [], alerts: [], backups: [], sources: [], ...over };
}

const healthy: DeviceHealth = { host_id: 1, hostname: 'core-sw-1', poll_status: 'ok' };
const unreachable: DeviceHealth = { host_id: 2, hostname: 'edge-rtr-1', poll_status: 'error' };

describe('buildIssues', () => {
  it('finds nothing wrong with healthy devices and sources', () => {
    expect(buildIssues(inputs({ devices: [healthy], sources: [source()] }))).toEqual([]);
  });

  it('names unreachable devices and points at the devices panel filtered to them', () => {
    const [issue] = buildIssues(inputs({ devices: [healthy, unreachable] }));
    expect(issue).toMatchObject({
      key: 'devices-down',
      count: 1,
      label: 'device unreachable',
      items: ['edge-rtr-1'],
      severity: 'critical',
      target: { to: devicesPanelLink('critical') },
    });
  });

  it('counts interfaces, not hosts, for interfaces down', () => {
    const devices: DeviceHealth[] = [
      { host_id: 1, hostname: 'core-sw-1', poll_status: 'ok', if_down_count: 2 },
      { host_id: 2, hostname: 'core-sw-2', poll_status: 'ok', if_down_count: 1 },
    ];
    const [issue] = buildIssues(inputs({ devices }));
    expect(issue.count).toBe(3);
    expect(issue.label).toBe('interfaces down on 2 hosts');
    expect(issue.items).toEqual(['core-sw-1 (2)', 'core-sw-2 (1)']);
  });

  it('reports a failed backup against its host', () => {
    const backups = [
      { id: 1, host_id: 1, hostname: 'core-sw-1', captured_at: new Date().toISOString(), status: 'failed' },
    ];
    const [issue] = buildIssues(inputs({ devices: [healthy], backups }));
    expect(issue).toMatchObject({ key: 'backups-failed', count: 1, target: { to: backupsPanelLink('failed') } });
  });

  it('takes the entity count from the totals, not the capped problem list', () => {
    const topo = topology({
      entity_counts: { up: 5, degraded: 0, down: 60, unknown: 0, total: 65 },
      problems: [problem()],
    });
    const [issue] = buildIssues(inputs({ topology: topo }));
    expect(issue.count).toBe(60);
    expect(issue.items).toHaveLength(1);
    expect(issue.target).toEqual({ to: topologyAvailabilityLink(null, { state: 'down' }) });
  });

  it('sends a failed source to Sources with its message', () => {
    const failed = source({ status: 'failed', message: 'API key rejected' });
    const [issue] = buildIssues(inputs({ sources: [failed] }));
    expect(issue).toMatchObject({
      key: 'sources-failed',
      label: 'source collection failed',
      items: ['Meraki: Example Org - API key rejected'],
      target: { to: SOURCES_LINK },
      action: 'Open Sources',
    });
  });

  it('lists critical issues before warnings, then the larger count first', () => {
    const devices: DeviceHealth[] = [
      { host_id: 1, hostname: 'core-sw-1', poll_status: 'ok', if_down_count: 9 },
      unreachable,
    ];
    const alerts = [
      { severity: 'critical', hostname: 'a', message: 'm' },
      { severity: 'critical', hostname: 'b', message: 'm' },
    ];
    expect(buildIssues(inputs({ devices, alerts })).map((i) => i.key)).toEqual([
      'alerts-critical',
      'devices-down',
      'interfaces-down',
    ]);
  });
});

describe('issueSummary', () => {
  const issue = (items: string[]): Issue => ({
    key: 'k',
    count: items.length,
    label: 'devices unreachable',
    items,
    severity: 'critical',
    target: ISSUE_ANCHORS.devices,
    action: 'Show devices',
  });

  it('names every item when they fit', () => {
    expect(issueSummary(issue(['a', 'b']))).toBe('a, b');
  });

  it('names the first few and counts the rest', () => {
    expect(issueSummary(issue(['a', 'b', 'c', 'd', 'e']))).toBe('a, b, c and 2 more');
  });

  it('is empty for an issue with no items', () => {
    expect(issueSummary(issue([]))).toBe('');
  });
});

describe('watchedSummary', () => {
  it('is empty when nothing is watched', () => {
    expect(watchedSummary({ devices: [], sources: [] })).toBe('');
  });

  it('does not count a source that has never collected, is disabled or is a demo', () => {
    const sources = [
      source({ status: 'never', last_collected_at: null }),
      source({ enabled: false }),
      source({ demo: true }),
    ];
    expect(watchedSummary({ devices: [], sources })).toBe('');
  });

  it('lists devices, sources and integration entities', () => {
    const topo = topology({ entity_counts: { up: 12, degraded: 0, down: 0, unknown: 0, total: 12 } });
    expect(watchedSummary({ devices: [healthy], sources: [source(), source({ id: 2 })], topology: topo })).toBe(
      '1 device, 2 sources, 12 integration entities',
    );
  });
});
