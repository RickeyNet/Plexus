import { describe, expect, it } from 'vitest';

import type { PathPick } from '@/pages/Topology/paths';

import { reachabilityFileUrl, reachabilitySearch, topologyExportUrl, type MerakiSubnet } from './meraki';

const subnet: MerakiSubnet = {
  org_ref: 1,
  cidr: '10.1.10.0/24',
  name: 'VLAN 10 Data',
  kind: 'vlan',
  site_id: 'L_1',
  site_name: 'Branch 01',
  node_id: 'mx1',
  in_vpn: true,
};

const picks: PathPick[] = [
  { key: 'n:12', node: 12, label: 'core-sw1' },
  { key: 's:1:10.1.10.5:mx1', node: 'meraki:1:mx1', label: '10.1.10.5 · Branch 01', subnet, address: '10.1.10.5' },
];

function query(url: string): URLSearchParams {
  return new URLSearchParams(url.split('?')[1] ?? '');
}

describe('topologyExportUrl', () => {
  it('builds the plain export URL', () => {
    expect(topologyExportUrl(null)).toBe('/api/topology/export.html');
    expect(topologyExportUrl(7, true)).toBe('/api/topology/export.html?group_id=7&download=1');
  });

  it('leaves out the path tracer only when asked', () => {
    expect(query(topologyExportUrl(null, true, null, false)).get('engine')).toBe('0');
    expect(query(topologyExportUrl(null, true, null)).get('engine')).toBeNull();
  });

  it('carries the open path and its traffic', () => {
    const url = topologyExportUrl(7, false, { picks, traffic: { protocol: 'tcp', port: 443 } });
    const params = query(url);
    expect(params.get('group_id')).toBe('7');
    expect(params.get('download')).toBeNull();
    expect(JSON.parse(params.get('path') ?? '')).toEqual({
      traffic: { protocol: 'tcp', port: 443 },
      picks: [
        { key: 'n:12', node: 12, label: 'core-sw1' },
        { key: 's:1:10.1.10.5:mx1', node: 'meraki:1:mx1', label: '10.1.10.5 · Branch 01', subnet, address: '10.1.10.5' },
      ],
    });
  });

  it('leaves the path out without picks', () => {
    expect(query(topologyExportUrl(null, true, { picks: [], traffic: { protocol: '' } })).has('path')).toBe(false);
    expect(query(topologyExportUrl(null, true, null)).has('path')).toBe(false);
  });
});

describe('reachabilitySearch', () => {
  it('keeps only the filters that are set', () => {
    const search = reachabilitySearch({
      destination: '10.0.10.20',
      protocol: 'tcp',
      port: 445,
      vlans: ' 100, 110-120 ',
      name: '',
      exclude: 'voice,guest',
      in_vpn: undefined,
    });
    const params = new URLSearchParams(search);
    expect([...params.keys()]).toEqual(['destination', 'protocol', 'port', 'vlans', 'exclude']);
    expect(params.get('vlans')).toBe('100, 110-120');
    expect(params.get('exclude')).toBe('voice,guest');
  });

  it('builds the file download URL with the same filters', () => {
    const sweep = { destination: '10.0.10.20', protocol: '', name: '/^VLAN 1\\d\\d /' };
    const url = reachabilityFileUrl(sweep);
    expect(url.startsWith('/api/topology/reachability?')).toBe(true);
    const params = query(url);
    expect(params.get('format')).toBe('xlsx');
    expect(params.get('name')).toBe('/^VLAN 1\\d\\d /');
    expect(params.has('protocol')).toBe(false);
    expect(params.has('verdict')).toBe(false);

    const shown = query(reachabilityFileUrl(sweep, 'csv', 'blocked'));
    expect(shown.get('format')).toBe('csv');
    expect(shown.get('verdict')).toBe('blocked');
    expect(query(reachabilityFileUrl(sweep, 'xlsx', null)).has('verdict')).toBe(false);
  });
});
