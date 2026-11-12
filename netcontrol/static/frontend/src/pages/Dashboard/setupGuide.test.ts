import { describe, expect, it } from 'vitest';

import type { TopologySource } from '@/api/meraki';

import {
  type SetupInputs,
  SETUP_LINKS,
  buildSetupSteps,
  hasCollected,
  isConnectedSource,
  notSetUpEntries,
  panelVisibility,
  setupProgress,
} from './setupGuide';

const NOW = Date.parse('2026-03-10T12:00:00Z');
const NOT_PENDING = { flowStatus: false, backupSummary: false };
const ALL = { topology: true, inventory: true, configBackups: true, trafficAnalysis: true };

function source(over: Partial<TopologySource> = {}): TopologySource {
  return {
    key: 'org:1',
    type: 'meraki',
    id: 1,
    name: 'Example Org',
    status: 'success',
    last_collected_at: new Date(NOW - 60_000).toISOString(),
    message: '',
    detail: '',
    warning_count: 0,
    collecting: false,
    can_collect: true,
    enabled: true,
    demo: false,
    ...over,
  };
}

// The two sources every install lists, never collected.
const BUILT_IN = [
  source({ key: 'neighbors', type: 'neighbors', id: null, status: 'never', last_collected_at: null }),
  source({ key: 'inventory', type: 'inventory', id: null, status: 'never', last_collected_at: null }),
];

function fresh(over: Partial<SetupInputs> = {}): SetupInputs {
  return {
    isAdmin: true,
    can: ALL,
    sources: BUILT_IN,
    totalHosts: 0,
    polledDevices: 0,
    snmpProfiles: 0,
    backupPolicies: 0,
    backups: 0,
    notificationChannels: 0,
    flowCollectorEnabled: false,
    ...over,
  };
}

const keys = (inp: SetupInputs) => buildSetupSteps(inp, NOW).map((s) => s.key);
const doneKeys = (inp: SetupInputs) =>
  buildSetupSteps(inp, NOW)
    .filter((s) => s.done)
    .map((s) => s.key);

describe('connected sources', () => {
  it('ignores the built-in, demo and disabled sources', () => {
    expect(BUILT_IN.some(isConnectedSource)).toBe(false);
    expect(isConnectedSource(source({ demo: true }))).toBe(false);
    expect(isConnectedSource(source({ type: 'aws', enabled: false }))).toBe(false);
    expect(isConnectedSource(source({ type: 'cato' }))).toBe(true);
    expect(isConnectedSource(source({ type: 'azure' }))).toBe(true);
  });

  it('counts a success or partial collection, not a failed or missing one', () => {
    expect(hasCollected(source(), NOW)).toBe(true);
    expect(hasCollected(source({ status: 'partial' }), NOW)).toBe(true);
    expect(hasCollected(source({ status: 'failed' }), NOW)).toBe(false);
    expect(hasCollected(source({ status: 'never', last_collected_at: null }), NOW)).toBe(false);
    expect(hasCollected({ ...BUILT_IN[1], status: 'success', last_collected_at: new Date(NOW).toISOString() }, NOW)).toBe(false);
  });
});

describe('buildSetupSteps', () => {
  it('lists every step for an admin on a fresh install, none done', () => {
    expect(keys(fresh())).toEqual(['source', 'collection', 'devices', 'polling', 'backups', 'notifications']);
    expect(doneKeys(fresh())).toEqual([]);
  });

  it('marks steps done from the data', () => {
    const inp = fresh({
      sources: [...BUILT_IN, source({ type: 'cato', status: 'never', last_collected_at: null })],
      totalHosts: 3,
      backupPolicies: 1,
    });
    expect(doneKeys(inp)).toEqual(['source', 'devices', 'backups']);
    const all = fresh({
      sources: [source()],
      totalHosts: 3,
      polledDevices: 2,
      snmpProfiles: 1,
      backupPolicies: 1,
      notificationChannels: 1,
    });
    expect(setupProgress(buildSetupSteps(all, NOW))).toEqual({ done: 6, total: 6, complete: true });
  });

  it('leaves out admin-only steps for other users', () => {
    expect(keys(fresh({ isAdmin: false }))).toEqual(['devices', 'backups']);
  });

  it('leaves out steps behind a feature the user lacks', () => {
    const can = { topology: false, inventory: false, configBackups: false, trafficAnalysis: false };
    expect(keys(fresh({ can }))).toEqual(['notifications']);
  });

  it('leaves out steps whose state is unknown', () => {
    const inp = fresh({ sources: undefined, notificationChannels: undefined, backupPolicies: undefined });
    expect(keys(inp)).toEqual(['devices', 'polling']);
  });

  it('links polling to the SNMP profiles dialog until one exists', () => {
    const polling = (n: number) => buildSetupSteps(fresh({ snmpProfiles: n }), NOW).find((s) => s.key === 'polling');
    expect(polling(0)?.action.to).toBe(SETUP_LINKS.snmpProfiles);
    expect(polling(2)?.action.to).toBe(SETUP_LINKS.monitoring);
  });

  it('is complete with no steps at all', () => {
    expect(setupProgress([]).complete).toBe(true);
  });
});

describe('panelVisibility', () => {
  it('hides what is not set up', () => {
    const vis = panelVisibility(fresh(), NOT_PENDING);
    expect(vis).toEqual({
      overview: 'hidden',
      groups: 'hidden',
      response: 'hidden',
      bandwidth: 'hidden',
      devices: 'hidden',
      health: 'hidden',
      talkers: 'hidden',
      backups: 'hidden',
    });
  });

  it('shows panels once set up', () => {
    const vis = panelVisibility(
      fresh({ polledDevices: 1, flowCollectorEnabled: true, backupPolicies: 0, backups: 4 }),
      NOT_PENDING,
    );
    expect(Object.values(vis).every((v) => v === 'shown')).toBe(true);
  });

  it('waits on a loading prerequisite and keeps a panel whose check failed', () => {
    const loading = fresh({ flowCollectorEnabled: undefined, backupPolicies: undefined, backups: undefined });
    const vis = panelVisibility(loading, { flowStatus: true, backupSummary: true });
    expect([vis.talkers, vis.backups]).toEqual(['pending', 'pending']);
    const failed = panelVisibility(loading, NOT_PENDING);
    expect([failed.talkers, failed.backups]).toEqual(['shown', 'shown']);
  });

  it('drops panels behind a feature the user lacks', () => {
    const can = { ...ALL, configBackups: false, trafficAnalysis: false };
    const vis = panelVisibility(fresh({ can }), NOT_PENDING);
    expect([vis.talkers, vis.backups]).toEqual(['absent', 'absent']);
  });
});

describe('notSetUpEntries', () => {
  it('groups the hidden panels by what they need', () => {
    const inp = fresh();
    const entries = notSetUpEntries(panelVisibility(inp, NOT_PENDING), inp);
    expect(entries.map((e) => e.key)).toEqual(['polling', 'flows', 'backups']);
    expect(entries[0].panels).toEqual([
      'Overall Health',
      'Group Health',
      'Average Response Time',
      'Busiest Interfaces',
      'Devices',
      'Device Health',
    ]);
    expect(entries.map((e) => e.action?.to)).toEqual([
      SETUP_LINKS.snmpProfiles,
      SETUP_LINKS.netflow,
      SETUP_LINKS.backupPolicy,
    ]);
  });

  it('offers no admin-only link to other users', () => {
    const inp = fresh({ isAdmin: false });
    const entries = notSetUpEntries(panelVisibility(inp, NOT_PENDING), inp);
    expect(entries.map((e) => e.action?.to)).toEqual([undefined, undefined, SETUP_LINKS.backupPolicy]);
  });

  it('is empty when everything is set up', () => {
    const inp = fresh({ polledDevices: 1, flowCollectorEnabled: true, backupPolicies: 1 });
    expect(notSetUpEntries(panelVisibility(inp, NOT_PENDING), inp)).toEqual([]);
  });
});
