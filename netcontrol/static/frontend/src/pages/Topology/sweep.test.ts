import { describe, expect, it } from 'vitest';

import type { MerakiSubnet, ReachabilityReport, ReachabilityRow, TopologySource } from '@/api/meraki';

import {
  buildReachabilityQuery,
  DEFAULT_SWEEP_KINDS,
  emptyForm,
  rowsWithVerdict,
  rowTraceQuery,
  siteRollup,
  SWEEP_PROVIDERS,
  sweepProviders,
  sweepSources,
  vlanTextError,
} from './sweep';

function row(fields: Partial<ReachabilityRow>): ReachabilityRow {
  return {
    org_ref: 1,
    org_name: 'Acme',
    provider: 'meraki',
    site_id: 'BR',
    site_name: 'Branch A',
    node_id: 'd:BR',
    source_node: 'meraki:1:d:BR',
    node_label: 'Branch A MX',
    kind: 'vlan',
    vlan: 10,
    cidr: '10.10.10.0/24',
    name: 'VLAN 10 Data',
    in_vpn: true,
    verdict: 'allowed',
    summary: 'Every hop allows it: Branch A MX → Hub MX.',
    traffic: 'tcp/445',
    decided_at: '',
    decided_by: '',
    ...fields,
  };
}

const ROWS: ReachabilityRow[] = [
  row({}),
  row({
    vlan: 30,
    cidr: '10.10.30.0/24',
    name: 'VLAN 30 Guest',
    in_vpn: false,
    verdict: 'blocked',
    decided_at: 'Branch A MX',
    decided_by: 'Layer 3 firewall rules: Rule 1 (deny any, "guest") denies it',
    summary: 'Blocked at Branch A MX, Layer 3 firewall rules: Rule 1 denies it',
  }),
  row({ site_name: 'Branch B', site_id: 'BB', cidr: '10.20.10.0/24', verdict: 'unknown', in_vpn: null, vlan: null }),
];

describe('vlanTextError', () => {
  it('accepts ids and ranges', () => {
    expect(vlanTextError('')).toBeNull();
    expect(vlanTextError('100, 110-120,5')).toBeNull();
    expect(vlanTextError('4095')).toBeNull();
  });

  it('names the part that is not valid', () => {
    expect(vlanTextError('100, ten')).toContain('"ten"');
    expect(vlanTextError('120-110')).toContain('"120-110"');
    expect(vlanTextError('5000')).toContain('"5000"');
  });
});

describe('buildReachabilityQuery', () => {
  it('builds the query and leaves the default kinds out', () => {
    const built = buildReachabilityQuery({
      ...emptyForm(),
      destination: ' 10.0.10.20 ',
      traffic: 'tcp/445',
      vlans: '100-120',
      exclude: 'voice,guest',
      sources: [1, 3],
      inVpn: '1',
    });
    expect(built).toEqual({
      query: {
        destination: '10.0.10.20',
        protocol: 'tcp',
        port: 445,
        sources: '1,3',
        providers: undefined,
        kinds: undefined,
        vlans: '100-120',
        name: undefined,
        exclude: 'voice,guest',
        sites: undefined,
        within: undefined,
        in_vpn: '1',
      },
    });
  });

  it('names kinds that are not the default set and the picked destination subnet', () => {
    const built = buildReachabilityQuery({
      ...emptyForm(),
      destination: '10.0.10.0/24',
      destinationOrgRef: 2,
      destinationNodeId: 'd:HUB',
      traffic: '',
      kinds: [...DEFAULT_SWEEP_KINDS, 'static'],
    });
    expect('query' in built && built.query).toMatchObject({
      protocol: '',
      port: undefined,
      kinds: 'vlan,lan,svi,range,subnet,connected,static',
      destination_org_ref: 2,
      destination_node_id: 'd:HUB',
    });
  });

  it('refuses a form that cannot run', () => {
    expect(buildReachabilityQuery({ ...emptyForm(), destination: '' })).toHaveProperty('error');
    expect(buildReachabilityQuery({ ...emptyForm(), destination: '10.0.0.1', traffic: 'gre' })).toHaveProperty('error');
    expect(buildReachabilityQuery({ ...emptyForm(), destination: '10.0.0.1', vlans: 'x' })).toHaveProperty('error');
    expect(buildReachabilityQuery({ ...emptyForm(), destination: '10.0.0.1', kinds: [] })).toHaveProperty('error');
  });
});

describe('rows', () => {
  it('filters by verdict', () => {
    expect(rowsWithVerdict(ROWS, null)).toHaveLength(3);
    expect(rowsWithVerdict(ROWS, 'blocked').map((r) => r.cidr)).toEqual(['10.10.30.0/24']);
  });

  it('rolls up per site', () => {
    expect(siteRollup(ROWS)).toEqual([
      { site: 'Branch A', checked: 2, counts: { allowed: 1, blocked: 1, unreachable: 0, partial: 0, unknown: 0 } },
      { site: 'Branch B', checked: 1, counts: { allowed: 0, blocked: 0, unreachable: 0, partial: 0, unknown: 1 } },
    ]);
  });

  it('traces a row again from its graph node to the destination', () => {
    const report = {
      destination: { address: '10.0.10.20', node: 'meraki:1:d:HUB', label: 'Hub MX', site: 'Hub' },
      traffic: 'tcp/445',
    } as ReachabilityReport;
    expect(rowTraceQuery(ROWS[0], report, { destination: '10.0.10.20', protocol: 'tcp', port: 445 })).toEqual({
      source: '10.10.10.0/24',
      destination: '10.0.10.20',
      source_node: 'meraki:1:d:BR',
      destination_node: 'meraki:1:d:HUB',
      protocol: 'tcp',
      port: 445,
    });
  });
});

describe('sweep filters with inventory networks', () => {
  const merakiSubnet: MerakiSubnet = {
    org_ref: 1, provider: 'meraki', cidr: '10.1.0.0/24', name: 'VLAN 1', kind: 'vlan',
    site_id: 'BR', site_name: 'Branch A', node_id: 'd:BR', in_vpn: true,
  };
  const inventorySubnet: MerakiSubnet = {
    org_ref: -4, provider: 'inventory', cidr: '10.50.0.0/24', name: 'VLAN 50 Users', kind: 'svi',
    site_id: '3', site_name: 'Campus', node_id: '12', in_vpn: null,
  };
  function source(fields: Partial<TopologySource>): TopologySource {
    return {
      key: 'meraki:1', type: 'meraki', id: 1, name: 'Acme', status: 'success', last_collected_at: null,
      message: '', detail: '', warning_count: 0, collecting: false, can_collect: true, enabled: true, demo: false,
      ...fields,
    };
  }
  const sources = [source({}), source({ key: 'neighbors', type: 'neighbors', id: null, name: 'Neighbor discovery' }), source({ key: 'aws:3', type: 'aws', id: 3, name: 'Prod' })];

  it('offers the inventory provider only when the index has inventory networks', () => {
    expect(sweepProviders([merakiSubnet])).toEqual(SWEEP_PROVIDERS);
    expect(sweepProviders([merakiSubnet, inventorySubnet])).toEqual([...SWEEP_PROVIDERS, 'inventory']);
  });

  it('adds an Inventory source with the inventory org_ref', () => {
    expect(sweepSources(sources, [merakiSubnet])).toEqual([{ key: 'meraki:1', id: 1, label: 'Acme (Meraki)' }]);
    expect(sweepSources(sources, [inventorySubnet])).toEqual([
      { key: 'meraki:1', id: 1, label: 'Acme (Meraki)' },
      { key: 'inventory', id: -4, label: 'Inventory' },
    ]);
  });

  it('groups inventory rows by their group, and a host with no group under Inventory', () => {
    const rows = [
      row({ org_ref: -4, org_name: 'Inventory', provider: 'inventory', site_name: 'Campus', node_id: '12' }),
      row({ org_ref: -4, org_name: 'Inventory', provider: 'inventory', site_name: '', node_id: '13' }),
    ];
    expect(siteRollup(rows).map((r) => r.site)).toEqual(['Campus', 'Inventory']);
  });
});
