import { describe, expect, it } from 'vitest';

import type { AuthStatus } from '@/api/auth';
import type { DeviceHealth } from '@/api/dashboard';

import {
  BACKUP_STATE_PARAM,
  DEVICES_FILTER_PARAM,
  DEVICE_HEALTH_FILTERS,
  HEALTH_GROUP_PARAM,
  HEALTH_STATUS_PARAM,
  backupsPanelLink,
  countDeviceHealthFilters,
  countNoun,
  dashboardLinkAccess,
  deviceHealthFilterOf,
  devicesPanelLink,
  healthTableLink,
  parseBackupState,
  parseDeviceHealthFilter,
  parseGroupKey,
} from './dashboardLinks';
import { ISSUE_ANCHORS, UNGROUPED_GROUP_KEY, deviceGroupKey, groupDevices } from './helpers';
import {
  AVAILABILITY_STATE_PARAM,
  AVAILABILITY_TYPE_PARAM,
  TOPOLOGY_AVAILABILITY_LINK,
  matchesAvailabilityState,
  parseAvailabilityEntityType,
  parseAvailabilitySource,
  parseAvailabilityState,
  topologyAvailabilityLink,
} from './sourceHealth';

/** The query of a link, as the destination reads it. */
function paramsOf(link: string): URLSearchParams {
  const url = new URL(link, 'https://plexus.example.com');
  return url.searchParams;
}

describe('device health buckets', () => {
  it('merges critical and down into one bucket', () => {
    expect(deviceHealthFilterOf('down')).toBe('critical');
    expect(deviceHealthFilterOf('critical')).toBe('critical');
    expect(deviceHealthFilterOf('warning')).toBe('warning');
    expect(deviceHealthFilterOf('healthy')).toBe('healthy');
    expect(deviceHealthFilterOf('unknown')).toBe('unknown');
  });

  it('counts each device under its bucket', () => {
    const devices: DeviceHealth[] = [
      { host_id: 1, poll_status: 'error' },
      { host_id: 2, cpu_percent: 95 },
      { host_id: 3, cpu_percent: 80 },
      { host_id: 4, cpu_percent: 10 },
      { host_id: 5 },
    ];
    expect(countDeviceHealthFilters(devices)).toEqual({ critical: 2, warning: 1, healthy: 1, unknown: 1 });
  });

  it('parses every bucket it lists and ignores anything else', () => {
    for (const f of DEVICE_HEALTH_FILTERS) expect(parseDeviceHealthFilter(f.key)).toBe(f.key);
    expect(parseDeviceHealthFilter('down')).toBeNull();
    expect(parseDeviceHealthFilter('all')).toBeNull();
    expect(parseDeviceHealthFilter('')).toBeNull();
    expect(parseDeviceHealthFilter(null)).toBeNull();
    expect(parseDeviceHealthFilter('CRITICAL')).toBeNull();
  });
});

describe('Dashboard panel links', () => {
  it('opens the Devices panel with a bucket the panel reads back', () => {
    const link = devicesPanelLink('critical');
    expect(link).toBe(`/?${DEVICES_FILTER_PARAM}=critical#${ISSUE_ANCHORS.devices}`);
    expect(parseDeviceHealthFilter(paramsOf(link).get(DEVICES_FILTER_PARAM))).toBe('critical');
  });

  it('opens the Devices panel unfiltered without a bucket', () => {
    expect(devicesPanelLink()).toBe(`/#${ISSUE_ANCHORS.devices}`);
    expect(devicesPanelLink(null)).toBe(`/#${ISSUE_ANCHORS.devices}`);
  });

  it('opens the health table with a group and a bucket', () => {
    const link = healthTableLink({ group: '7', health: 'warning' });
    expect(link).toBe(`/?${HEALTH_GROUP_PARAM}=7&${HEALTH_STATUS_PARAM}=warning#${ISSUE_ANCHORS.health}`);
    const params = paramsOf(link);
    expect(parseGroupKey(params.get(HEALTH_GROUP_PARAM))).toBe('7');
    expect(parseDeviceHealthFilter(params.get(HEALTH_STATUS_PARAM))).toBe('warning');
  });

  it('opens the health table with only a group', () => {
    expect(healthTableLink({ group: UNGROUPED_GROUP_KEY })).toBe(
      `/?${HEALTH_GROUP_PARAM}=${UNGROUPED_GROUP_KEY}#${ISSUE_ANCHORS.health}`,
    );
  });

  it('opens the Backup Status panel with a state it reads back', () => {
    const link = backupsPanelLink('failed');
    expect(link).toBe(`/?${BACKUP_STATE_PARAM}=failed#${ISSUE_ANCHORS.backups}`);
    expect(parseBackupState(paramsOf(link).get(BACKUP_STATE_PARAM))).toBe('failed');
    expect(backupsPanelLink(null)).toBe(`/#${ISSUE_ANCHORS.backups}`);
  });

  it('ignores unknown backup states and blank or oversized group keys', () => {
    expect(parseBackupState('broken')).toBeNull();
    expect(parseBackupState(null)).toBeNull();
    for (const s of ['success', 'stale', 'failed', 'never']) expect(parseBackupState(s)).toBe(s);
    expect(parseGroupKey('  ')).toBeNull();
    expect(parseGroupKey(null)).toBeNull();
    expect(parseGroupKey('x'.repeat(65))).toBeNull();
  });
});

describe('device groups', () => {
  it('keys a device by its group, or as ungrouped', () => {
    expect(deviceGroupKey({ group_id: 3 })).toBe('3');
    expect(deviceGroupKey({})).toBe(UNGROUPED_GROUP_KEY);
  });

  it('lists every group, then groups only devices name, then Ungrouped', () => {
    const groups = [
      { id: 1, name: 'Core' },
      { id: 2, name: 'Empty' },
    ];
    const devices: DeviceHealth[] = [
      { host_id: 1, hostname: 'edge-rtr-1' },
      { host_id: 2, hostname: 'core-sw-1', group_id: 1, group_name: 'Core' },
      { host_id: 3, hostname: 'lab-sw-1', group_id: 9, group_name: 'Lab' },
    ];
    const out = groupDevices(groups, devices);
    expect(out.map((g) => [g.key, g.name, g.devices.length])).toEqual([
      ['1', 'Core', 1],
      ['2', 'Empty', 0],
      ['9', 'Lab', 1],
      [UNGROUPED_GROUP_KEY, 'Ungrouped', 1],
    ]);
  });
});

describe('availability links', () => {
  it('keeps the plain link when nothing is filtered', () => {
    expect(topologyAvailabilityLink()).toBe(TOPOLOGY_AVAILABILITY_LINK);
    expect(topologyAvailabilityLink(null, {})).toBe(TOPOLOGY_AVAILABILITY_LINK);
  });

  it('filters by source, type and state, each read back by the panel', () => {
    const link = topologyAvailabilityLink({ provider: 'cato', orgRef: 11 }, { entityType: 'tunnel', state: 'down' });
    const params = paramsOf(link);
    expect(parseAvailabilitySource(params.get('source'))).toEqual({ provider: 'cato', orgRef: 11 });
    expect(parseAvailabilityEntityType(params.get(AVAILABILITY_TYPE_PARAM))).toBe('tunnel');
    expect(parseAvailabilityState(params.get(AVAILABILITY_STATE_PARAM))).toBe('down');
    expect(link.endsWith('#topology-availability')).toBe(true);
  });

  it('filters by state alone across every source', () => {
    const link = topologyAvailabilityLink(null, { state: 'problem' });
    expect(link).toBe('/monitoring/availability?state=problem#topology-availability');
  });

  it('ignores unknown states and entity types', () => {
    expect(parseAvailabilityState('broken')).toBeNull();
    expect(parseAvailabilityState(null)).toBeNull();
    expect(parseAvailabilityEntityType('router')).toBeNull();
    expect(parseAvailabilityEntityType(undefined)).toBeNull();
    expect(parseAvailabilityEntityType('vpn_connection')).toBe('vpn_connection');
  });

  it('matches down or degraded for the problem filter', () => {
    expect(matchesAvailabilityState('down', 'problem')).toBe(true);
    expect(matchesAvailabilityState('degraded', 'problem')).toBe(true);
    expect(matchesAvailabilityState('up', 'problem')).toBe(false);
    expect(matchesAvailabilityState('up', 'up')).toBe(true);
    expect(matchesAvailabilityState('unknown', 'down')).toBe(false);
  });
});

describe('dashboardLinkAccess', () => {
  const auth = (over: Partial<AuthStatus>): AuthStatus => ({ role: 'user', ...over }) as AuthStatus;

  it('links only to pages the user may open', () => {
    expect(dashboardLinkAccess(auth({ feature_access: ['inventory', 'monitoring'] }))).toEqual({
      inventory: true,
      playbooks: false,
      jobs: false,
      monitoring: true,
      topology: false,
    });
  });

  it('opens everything to an admin except what is hidden globally', () => {
    const access = dashboardLinkAccess(auth({ role: 'admin', feature_visibility_hidden: ['jobs'] }));
    expect(access).toEqual({ inventory: true, playbooks: true, jobs: false, monitoring: true, topology: true });
  });

  it('links nowhere before the auth status is known', () => {
    expect(Object.values(dashboardLinkAccess(undefined)).some(Boolean)).toBe(false);
  });
});

describe('countNoun', () => {
  it('picks the singular for one', () => {
    expect(countNoun(1, 'host', 'hosts')).toBe('1 host');
    expect(countNoun(0, 'host', 'hosts')).toBe('0 hosts');
  });
});
