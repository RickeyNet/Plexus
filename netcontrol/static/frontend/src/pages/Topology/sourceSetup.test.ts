import { describe, expect, it } from 'vitest';

import type { ImportableDevice, ImportDevicesResult } from '@/api/sourceImport';

import {
  backupCapableCount,
  buildImportRequest,
  capabilityText,
  defaultSelection,
  describeImportResult,
  filterDevices,
  importBlocker,
  snmpCapableCount,
  soleProfileId,
  stepState,
  toggleDevice,
} from './sourceSetup';

function device(key: string, fields: Partial<ImportableDevice> = {}): ImportableDevice {
  return {
    key,
    name: key,
    ip: '192.0.2.1',
    model: '',
    serial: '',
    kind: 'appliance',
    site: '',
    platform: '',
    device_type: 'icmp_only',
    capabilities: { snmp_polling: false, config_backup: false },
    existing: null,
    ...fields,
  };
}

const existing = {
  host_id: 7,
  hostname: 'fw-a',
  ip_address: '192.0.2.9',
  group_id: 1,
  group_name: 'Firewalls',
};

const ftd = device('d:1', {
  name: 'ftd-east',
  ip: '192.0.2.10',
  model: 'Firepower 1120',
  site: 'East',
  device_type: 'cisco_ftd',
  capabilities: { snmp_polling: true, config_backup: false },
});
const core = device('x:1', {
  name: 'core-sw',
  ip: '198.51.100.2',
  device_type: 'cisco_xe',
  capabilities: { snmp_polling: true, config_backup: true },
});
const known = device('d:2', { name: 'fw-a', ip: '192.0.2.9', existing });
const ap = device('d:3', { name: 'ap-1', ip: '203.0.113.4' });

describe('stepState', () => {
  it('marks earlier steps done, the current one current and later ones to do', () => {
    expect(stepState('credentials', 'collecting')).toBe('done');
    expect(stepState('collecting', 'collecting')).toBe('current');
    expect(stepState('import', 'collecting')).toBe('todo');
  });
});

describe('selection', () => {
  it('preselects every device not in the inventory, up to the limit', () => {
    expect([...defaultSelection([ftd, known, core, ap], 10)]).toEqual(['d:1', 'x:1', 'd:3']);
    expect([...defaultSelection([ftd, known, core, ap], 2)]).toEqual(['d:1', 'x:1']);
  });

  it('toggles a device but never selects one in the inventory or past the limit', () => {
    const none = new Set<string>();
    expect([...toggleDevice(none, ftd, 5)]).toEqual(['d:1']);
    expect([...toggleDevice(new Set(['d:1']), ftd, 5)]).toEqual([]);
    expect([...toggleDevice(none, known, 5)]).toEqual([]);
    expect([...toggleDevice(new Set(['d:1']), core, 1)]).toEqual(['d:1']);
  });

  it('filters by name, address, model, site and device type', () => {
    const all = [ftd, core, ap];
    expect(filterDevices(all, '').length).toBe(3);
    expect(filterDevices(all, 'EAST').map((d) => d.key)).toEqual(['d:1']);
    expect(filterDevices(all, '198.51').map((d) => d.key)).toEqual(['x:1']);
    expect(filterDevices(all, 'cisco_xe').map((d) => d.key)).toEqual(['x:1']);
    expect(filterDevices(all, 'firepower').map((d) => d.key)).toEqual(['d:1']);
  });

  it('counts the selected devices that can be polled and backed up', () => {
    const selected = new Set(['d:1', 'x:1', 'd:3']);
    expect(snmpCapableCount([ftd, core, ap], selected)).toBe(2);
    expect(backupCapableCount([ftd, core, ap], selected)).toBe(1);
    expect(backupCapableCount([ftd, core, ap], new Set(['d:1']))).toBe(0);
  });
});

describe('capabilityText', () => {
  it('says what Plexus does with the device', () => {
    expect(capabilityText(ap)).toBe('Ping only');
    expect(capabilityText(ftd)).toBe('Ping and SNMP');
    expect(capabilityText(core)).toBe('Ping, SNMP and config backup');
  });
});

describe('soleProfileId', () => {
  it('preselects a profile only when there is exactly one', () => {
    expect(soleProfileId(undefined)).toBe('');
    expect(soleProfileId([])).toBe('');
    expect(soleProfileId([{ id: 'p1' }])).toBe('p1');
    expect(soleProfileId([{ id: 'p1' }, { id: 'p2' }])).toBe('');
  });
});

describe('import request', () => {
  const choices = { target: { mode: 'new' as const, name: ' Branch FMC ' }, profileId: '', backupCredentialId: null };

  it('says why it cannot be sent yet', () => {
    expect(importBlocker(0, choices)).toMatch(/at least one/);
    expect(importBlocker(1, { ...choices, target: { mode: 'new', name: '  ' } })).toMatch(/Name/);
    expect(importBlocker(1, { ...choices, target: { mode: 'existing', groupId: null } })).toMatch(/Choose/);
    expect(importBlocker(1, choices)).toBeNull();
  });

  it('names the selected devices in list order and only the choices made', () => {
    const selected = new Set(['x:1', 'd:1']);
    expect(buildImportRequest([ftd, core, ap], selected, choices)).toEqual({
      device_keys: ['d:1', 'x:1'],
      new_group_name: 'Branch FMC',
    });
    expect(
      buildImportRequest([ftd, core], selected, {
        target: { mode: 'existing', groupId: 4 },
        profileId: 'p1',
        backupCredentialId: 9,
      }),
    ).toEqual({ device_keys: ['d:1', 'x:1'], group_id: 4, snmp_profile_id: 'p1', backup_credential_id: 9 });
  });
});

describe('describeImportResult', () => {
  const base: ImportDevicesResult = {
    ok: true,
    group: { id: 3, name: 'Branch FMC', created: true },
    added: [],
    skipped: [],
    errors: [],
    counts: { added: 2, skipped: 1, errors: 0 },
    snmp_profile: { status: 'assigned', profile_id: 'p1', profile_name: 'Read-only' },
    backup_policy: {
      status: 'created',
      policy_id: 5,
      name: 'Branch FMC daily backup',
      interval_seconds: 86400,
      retention_days: 30,
    },
    monitoring_enabled: true,
  };

  it('states every outcome in words', () => {
    expect(describeImportResult(base)).toEqual([
      '2 devices added to the new group "Branch FMC".',
      '1 device already in the inventory, left as they are.',
      'SNMP profile "Read-only" assigned to the group.',
      'Backup policy "Branch FMC daily backup" created: daily, backups kept for 30 days.',
    ]);
  });

  it('reports a kept profile, an existing policy and monitoring being off', () => {
    const lines = describeImportResult({
      ...base,
      group: { ...base.group, created: false },
      counts: { added: 1, skipped: 0, errors: 1 },
      snmp_profile: { status: 'kept', profile_id: 'p2', profile_name: 'Core' },
      backup_policy: { status: 'exists', policy_id: 2, name: 'Nightly' },
      monitoring_enabled: false,
    });
    expect(lines).toEqual([
      '1 device added to group "Branch FMC".',
      '1 device could not be added.',
      'The group already uses SNMP profile "Core"; it was kept.',
      'The group\'s backup policy "Nightly" now covers these devices too.',
      'Monitoring is turned off: nothing is polled until it is turned on.',
    ]);
  });
});
