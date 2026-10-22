import { describe, expect, it } from 'vitest';

import type { TopologyNode } from '@/api/topology';
import { DEVICE_TYPES } from '@/lib/deviceTypes';

import {
  buildBulkAddBody,
  buildInventoryAddRows,
  DEFAULT_ADD_GROUP,
  DISCOVERED_NEIGHBORS_GROUP,
  filterInventoryAddRows,
  GROUP_NAME_MAX,
  guessDeviceType,
  resolvedGroupPath,
  suggestedGroups,
  suggestGroupPath,
} from './inventoryAdd';

const guess = (model: string, platform = '') => guessDeviceType({ model, platform, device_type: 'unknown' });

describe('guessDeviceType', () => {
  it('maps Catalyst and IOS platforms to IOS-XE', () => {
    expect(guess('cisco C9410R')).toBe('cisco_xe');
    expect(guess('WS-C3850-48P')).toBe('cisco_xe');
    expect(guess('', 'Cisco Catalyst 9300')).toBe('cisco_xe');
    expect(guess('', 'Cisco IOS Software, C2960X')).toBe('cisco_xe');
    expect(guess('', 'Cisco IOS XE Software')).toBe('cisco_xe');
  });

  it('falls back to IOS when the list has no IOS-XE', () => {
    const noXe = DEVICE_TYPES.filter((t) => t.value !== 'cisco_xe');
    expect(guessDeviceType({ model: 'cisco C9410R' }, noXe)).toBe('cisco_ios');
  });

  it('recognises the other vendors', () => {
    expect(guess('N9K-C93180YC-EX', 'Cisco NX-OS(tm) n9000')).toBe('cisco_nxos');
    expect(guess('cisco Nexus 7000')).toBe('cisco_nxos');
    expect(guess('Cisco ASA5516-X')).toBe('cisco_asa');
    expect(guess('Cisco Firepower 2130 Threat Defense')).toBe('cisco_ftd');
    expect(guess('', 'Cisco IOS XR Software')).toBe('cisco_xr');
    expect(guess('Arista DCS-7050SX')).toBe('arista_eos');
    expect(guess('Juniper EX4300')).toBe('juniper_junos');
    expect(guess('FortiGate-100F')).toBe('fortinet');
    expect(guess('Palo Alto Networks PA-3220')).toBe('paloalto_panos');
    expect(guess('Aruba 6300M', 'ArubaOS-CX')).toBe('aruba_aoscx');
    expect(guess('HP ProCurve 2920')).toBe('aruba_osswitch');
  });

  it('makes unknown and Linux devices ICMP-only', () => {
    expect(guess('')).toBe('icmp_only');
    expect(guess('Linux 5.15')).toBe('icmp_only');
    expect(guess('MX450')).toBe('icmp_only');
    const noIcmp = DEVICE_TYPES.filter((t) => t.value !== 'icmp_only');
    expect(guessDeviceType({ model: 'Linux' }, noIcmp)).toBe('cisco_ios');
  });

  it('keeps a device type the node already has', () => {
    expect(guessDeviceType({ model: 'Linux', device_type: 'arista_eos' })).toBe('arista_eos');
  });
});

const node = (over: Partial<TopologyNode>): TopologyNode => ({
  id: over.id ?? String(over.label),
  label: 'x',
  in_inventory: false,
  ...over,
});

const NODES: TopologyNode[] = [
  node({ id: 'meraki:1:x:N_1:aa', label: 'dist-b', ip: '10.0.0.2', model: 'cisco C9410R', meraki: { org_ref: 1, node_id: 'aa', site_id: 'N_1', site_name: 'HQ', kind: 'neighbor', status: '' } }),
  node({ id: 'meraki:1:x:N_2:aa', label: 'dist-b (again)', ip: '10.0.0.2', model: 'cisco C9410R' }),
  node({ id: 'ext_core-a', label: 'core-a', ip: ' 10.0.0.1 ', platform: 'Cisco NX-OS', group_name: 'Core' }),
  node({ id: 7, label: 'inv-host', ip: '10.0.0.3', in_inventory: true }),
  node({ id: 'ext_phone', label: 'phone', ip: '' }),
  node({ id: 'ext_null', label: 'nulled', ip: null }),
  node({ id: 'meraki:1:d:Q2XX', label: 'Branch MX', ip: '10.0.0.9', model: 'MX68', source: 'meraki', meraki: { org_ref: 1, node_id: 'd:Q2XX', site_id: 'N_1', site_name: 'HQ', kind: 'appliance', status: 'online' } }),
];

const MERAKI_HQ = { org_ref: 1, node_id: 'aa', site_id: 'N_1', site_name: 'HQ', kind: 'neighbor', status: '' };

describe('suggestGroupPath', () => {
  it('puts a neighbor a Meraki device reported in that Meraki site, under Meraki', () => {
    expect(suggestGroupPath({ meraki: MERAKI_HQ })).toEqual(['Meraki', 'HQ']);
    expect(suggestGroupPath({ source: 'meraki', meraki: { ...MERAKI_HQ, provider: 'meraki' } })).toEqual(['Meraki', 'HQ']);
  });

  it('puts a cloud instance in a sub-group per VPC under its provider', () => {
    const vpc = { ...MERAKI_HQ, site_name: '  prod-vpc ', kind: 'instance', provider: 'aws' };
    expect(suggestGroupPath({ source: 'meraki', meraki: vpc })).toEqual(['AWS', 'prod-vpc']);
  });

  it('puts an SNMP neighbor under Discovered neighbors, named after the group that reported it', () => {
    expect(suggestGroupPath({ group_name: 'Core  switches' })).toEqual([DISCOVERED_NEIGHBORS_GROUP, 'Core switches']);
  });

  it('falls back to one top-level group for a bare node, and caps long names', () => {
    expect(suggestGroupPath({})).toEqual([DEFAULT_ADD_GROUP]);
    const [, leaf] = suggestGroupPath({ group_name: 'x'.repeat(300) });
    expect(leaf).toHaveLength(GROUP_NAME_MAX);
  });
});

describe('buildInventoryAddRows', () => {
  it('keeps nodes outside inventory that have an IP, one per IP, sorted by label', () => {
    const rows = buildInventoryAddRows(NODES);
    expect(rows).toEqual([
      { ip: '10.0.0.1', nodeId: 'ext_core-a', label: 'core-a', platform: 'Cisco NX-OS', site: 'Core', groupPath: [DISCOVERED_NEIGHBORS_GROUP, 'Core'], group: 'Discovered neighbors / Core', deviceType: 'cisco_nxos', managed: false },
      { ip: '10.0.0.2', nodeId: 'meraki:1:x:N_1:aa', label: 'dist-b', platform: 'cisco C9410R', site: 'HQ', groupPath: ['Meraki', 'HQ'], group: 'Meraki / HQ', deviceType: 'cisco_xe', managed: false },
    ]);
  });

  it('names an SNMP neighbor after the inventory host that reported it', () => {
    const nodes = [
      node({ id: 3, label: 'core-1', ip: '10.1.0.1', in_inventory: true, group_name: 'Campus' }),
      node({ id: 'ext_ap', label: 'ap', ip: '10.1.0.9' }),
      node({ id: 'ext_lone', label: 'lone', ip: '10.1.0.8' }),
    ];
    const rows = buildInventoryAddRows(nodes, DEVICE_TYPES, false, [{ id: 'e1', from: 3, to: 'ext_ap' }]);
    expect(rows.map((r) => [r.label, r.site, r.groupPath])).toEqual([
      ['ap', 'Campus', [DISCOVERED_NEIGHBORS_GROUP, 'Campus']],
      ['lone', '', [DEFAULT_ADD_GROUP]],
    ]);
  });

  it('treats only Meraki devices as cloud-managed, not other integrations', () => {
    const aws = node({ id: 'meraki:2:i-1', label: 'vm', ip: '10.2.0.1', source: 'meraki', meraki: { ...MERAKI_HQ, site_name: 'prod-vpc', provider: 'aws' } });
    expect(buildInventoryAddRows([aws]).map((r) => [r.label, r.managed, r.group])).toEqual([['vm', false, 'AWS / prod-vpc']]);
  });

  it('leaves Meraki hardware out unless asked, since it has no CLI', () => {
    expect(buildInventoryAddRows(NODES).some((r) => r.managed)).toBe(false);
    const withManaged = buildInventoryAddRows(NODES, DEVICE_TYPES, true);
    expect(withManaged.map((r) => [r.label, r.managed, r.deviceType])).toEqual([
      ['Branch MX', true, 'icmp_only'],
      ['core-a', false, 'cisco_nxos'],
      ['dist-b', false, 'cisco_xe'],
    ]);
  });

  it('filters rows by label, IP, platform, site or group', () => {
    const rows = buildInventoryAddRows(NODES);
    expect(filterInventoryAddRows(rows, '').length).toBe(2);
    expect(filterInventoryAddRows(rows, 'hq').map((r) => r.ip)).toEqual(['10.0.0.2']);
    expect(filterInventoryAddRows(rows, 'NX-OS').map((r) => r.ip)).toEqual(['10.0.0.1']);
    expect(filterInventoryAddRows(rows, 'discovered').map((r) => r.ip)).toEqual(['10.0.0.1']);
    expect(filterInventoryAddRows(rows, '10.0.0.')).toHaveLength(2);
    expect(filterInventoryAddRows(rows, 'nothing')).toEqual([]);
  });
});

describe('buildBulkAddBody', () => {
  const rows = buildInventoryAddRows(NODES);
  const both = new Set(['10.0.0.2', '10.0.0.1']);

  it('sends each selected row to its group path in automatic mode, renaming the leaf', () => {
    expect(
      buildBulkAddBody(rows, both, { '10.0.0.1': 'icmp_only' }, { mode: 'auto', renames: { 'Meraki / HQ': '  HQ  site ' } }),
    ).toEqual({
      hosts: [
        { hostname: 'core-a', ip_address: '10.0.0.1', device_type: 'icmp_only', group_path: [DISCOVERED_NEIGHBORS_GROUP, 'Core'] },
        { hostname: 'dist-b', ip_address: '10.0.0.2', device_type: 'cisco_xe', group_path: ['Meraki', 'HQ site'] },
      ],
    });
    // A rename cleared back to nothing keeps the suggestion.
    const cleared = buildBulkAddBody(rows, both, {}, { mode: 'auto', renames: { 'Meraki / HQ': ' ' } });
    expect(cleared.hosts.map((h) => h.group_path)).toEqual([[DISCOVERED_NEIGHBORS_GROUP, 'Core'], ['Meraki', 'HQ']]);
    expect(buildBulkAddBody(rows, new Set(), {}, { mode: 'auto' })).toEqual({ hosts: [] });
  });

  it('renames a single-level group itself', () => {
    const [lone] = buildInventoryAddRows([node({ id: 'ext_lone', label: 'lone', ip: '10.1.0.8' })]);
    expect(resolvedGroupPath(lone, { [DEFAULT_ADD_GROUP]: 'Strays' })).toEqual(['Strays']);
  });

  it('sends every selected row to one group in single mode', () => {
    expect(buildBulkAddBody(rows, both, {}, { mode: 'single', groupId: 4 })).toEqual({
      group_id: 4,
      hosts: [
        { hostname: 'core-a', ip_address: '10.0.0.1', device_type: 'cisco_nxos' },
        { hostname: 'dist-b', ip_address: '10.0.0.2', device_type: 'cisco_xe' },
      ],
    });
  });

  it('lists the group paths automatic mode will use, with counts', () => {
    const third = buildInventoryAddRows([
      ...NODES,
      node({ id: 'meraki:1:x:N_1:bb', label: 'dist-c', ip: '10.0.0.4', meraki: { ...MERAKI_HQ, node_id: 'bb' } }),
    ]);
    expect(suggestedGroups(third, new Set([...both, '10.0.0.4']))).toEqual([
      { group: 'Discovered neighbors / Core', path: [DISCOVERED_NEIGHBORS_GROUP, 'Core'], count: 1 },
      { group: 'Meraki / HQ', path: ['Meraki', 'HQ'], count: 2 },
    ]);
    expect(resolvedGroupPath(rows[1], { 'Meraki / HQ': 'Renamed' })).toEqual(['Meraki', 'Renamed']);
  });
});
