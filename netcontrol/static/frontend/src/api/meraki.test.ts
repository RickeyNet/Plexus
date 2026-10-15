import { describe, expect, it } from 'vitest';

import type { PathPick } from '@/pages/Topology/paths';

import { topologyExportUrl, type MerakiSubnet } from './meraki';

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
