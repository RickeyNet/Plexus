import { describe, expect, it } from 'vitest';

import type { MerakiSubnet, NetworkRow, ReachabilityReport, ReachabilityRow, TopologySource } from '@/api/meraki';

import {
  buildListQuery,
  buildReachabilityQuery,
  cloudsToMerakiForm,
  DEFAULT_SWEEP_KINDS,
  emptyFilters,
  emptyForm,
  endOwnerPatch,
  endPatch,
  isListQuery,
  isMatrixQuery,
  isTraceRow,
  isTypedSource,
  LIST_TYPED_SOURCE_ERROR,
  MATRIX_NARROW_ERROR,
  withSingleOwners,
  pairRollup,
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
    dst_cidr: '10.0.10.20',
    dst_name: '',
    dst_site_name: 'Hub',
    dst_org_ref: null,
    dst_org_name: '',
    dst_provider: '',
    dst_node_id: '',
    dst_node_label: 'Hub MX',
    dst_kind: '',
    dst_vlan: null,
    dst_in_vpn: null,
    destination_node: null,
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
    expect(buildReachabilityQuery({ ...emptyForm(), destination: '' })).toEqual({ error: MATRIX_NARROW_ERROR });
    expect(buildReachabilityQuery({ ...emptyForm(), destination: '10.0.0.1', traffic: 'gre' })).toHaveProperty('error');
    expect(buildReachabilityQuery({ ...emptyForm(), destination: '10.0.0.1', vlans: 'x' })).toHaveProperty('error');
    expect(buildReachabilityQuery({ ...emptyForm(), destination: '10.0.0.1', kinds: [] })).toHaveProperty('error');
  });

  it('never sends the destination filters with a destination', () => {
    const built = buildReachabilityQuery({
      ...emptyForm(),
      destination: '10.0.0.1',
      to: { ...emptyFilters(), providers: ['meraki'], sites: 'hub', vlans: 'x' },
    });
    expect('query' in built).toBe(true);
    if (!('query' in built)) return;
    expect(Object.keys(built.query).filter((key) => key.startsWith('to_'))).toEqual([]);
    expect(isMatrixQuery(built.query)).toBe(false);
  });

  it('builds a matrix query from the destination filters', () => {
    const built = buildReachabilityQuery({
      ...emptyForm(),
      destination: '  ',
      destinationOrgRef: 2,
      destinationNodeId: 'd:HUB',
      providers: ['aws'],
      to: { ...emptyFilters(), providers: ['meraki'], sources: [1], vlans: '10-20', inVpn: '1' },
    });
    expect(built).toEqual({
      query: {
        protocol: 'tcp',
        port: 445,
        providers: 'aws',
        to_providers: 'meraki',
        to_sources: '1',
        to_vlans: '10-20',
        to_in_vpn: '1',
      },
    });
    if (!('query' in built)) return;
    expect(built.query).not.toHaveProperty('destination');
    expect(built.query).not.toHaveProperty('destination_node');
    expect(built.query).not.toHaveProperty('destination_org_ref');
    expect(built.query).not.toHaveProperty('destination_node_id');
    expect(built.query.to_kinds).toBeUndefined();
    expect(isMatrixQuery(built.query)).toBe(true);
  });

  it('names destination kinds that are not the default set', () => {
    const built = buildReachabilityQuery({
      ...emptyForm(),
      to: { ...emptyFilters(), name: 'data', kinds: ['vlan'] },
    });
    expect('query' in built && built.query).toMatchObject({ to_name: 'data', to_kinds: 'vlan' });
  });

  it('refuses a matrix that does not narrow the destinations, or has bad destination filters', () => {
    // Exclude and In VPN alone keep nearly every network.
    expect(buildReachabilityQuery({ ...emptyForm(), to: { ...emptyFilters(), exclude: 'guest', inVpn: '1' } })).toEqual({
      error: MATRIX_NARROW_ERROR,
    });
    expect(buildReachabilityQuery({ ...emptyForm(), to: { ...emptyFilters(), vlans: '10, x' } })).toHaveProperty('error');
    expect(
      buildReachabilityQuery({ ...emptyForm(), to: { ...emptyFilters(), providers: ['meraki'], kinds: [] } }),
    ).toHaveProperty('error');
  });

  it('presets clouds and Cato to Meraki with any traffic', () => {
    const form = cloudsToMerakiForm();
    expect(form.destination).toBe('');
    expect(form.traffic).toBe('');
    expect(form.providers).toEqual(['aws', 'azure', 'gcp', 'cato']);
    expect(form.to.providers).toEqual(['meraki']);
    expect(form.to.kinds).toEqual(DEFAULT_SWEEP_KINDS);
    expect(buildReachabilityQuery(form)).toEqual({
      query: { protocol: '', port: undefined, providers: 'aws,azure,gcp,cato', to_providers: 'meraki' },
    });
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
      mode: 'one',
      destination: { address: '10.0.10.20', node: 'meraki:1:d:HUB', label: 'Hub MX', site: 'Hub' },
      traffic: 'tcp/445',
    } as ReachabilityReport;
    const query = { destination: '10.0.10.20', protocol: 'tcp', port: 445 };
    expect(rowTraceQuery(ROWS[0], report, query)).toEqual({
      source: '10.10.10.0/24',
      destination: '10.0.10.20',
      source_node: 'meraki:1:d:BR',
      destination_node: 'meraki:1:d:HUB',
      protocol: 'tcp',
      port: 445,
    });
    // The row's own end node wins over the report's.
    expect(rowTraceQuery(row({ destination_node: 9 }), report, query).destination_node).toBe(9);
  });

  it('traces a matrix row to its own destination network and node', () => {
    const report = { mode: 'matrix', destination: null, traffic: 'any traffic' } as ReachabilityReport;
    const matrixRow = row({ dst_cidr: '10.30.0.0/24', destination_node: 'meraki:1:d:STORE' });
    expect(rowTraceQuery(matrixRow, report, { protocol: '' })).toEqual({
      source: '10.10.10.0/24',
      destination: '10.30.0.0/24',
      source_node: 'meraki:1:d:BR',
      destination_node: 'meraki:1:d:STORE',
      protocol: '',
      port: undefined,
    });
  });

  it('rolls up per source and destination site pair', () => {
    const rows = [
      row({ dst_site_name: 'Store 1' }),
      row({ dst_site_name: 'Store 2', verdict: 'blocked' }),
      row({ dst_site_name: 'Store 1', verdict: 'partial' }),
      row({ site_name: '', org_name: 'AWS prod', dst_site_name: '', dst_org_name: '', dst_node_label: '' }),
    ];
    expect(pairRollup(rows)).toEqual([
      {
        source: 'Branch A',
        destination: 'Store 1',
        checked: 2,
        counts: { allowed: 1, blocked: 0, unreachable: 0, partial: 1, unknown: 0 },
      },
      {
        source: 'Branch A',
        destination: 'Store 2',
        checked: 1,
        counts: { allowed: 0, blocked: 1, unreachable: 0, partial: 0, unknown: 0 },
      },
      {
        source: 'AWS prod',
        destination: 'No site',
        checked: 1,
        counts: { allowed: 1, blocked: 0, unreachable: 0, partial: 0, unknown: 0 },
      },
    ]);
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

const SOURCE_FILTER_KEYS = ['sources', 'providers', 'kinds', 'vlans', 'name', 'exclude', 'sites', 'within', 'in_vpn'];

/** A typed source's row: no snapshot network, the trace's source node and site. */
function typedRow(fields: Partial<ReachabilityRow>): ReachabilityRow {
  return row({
    org_ref: null,
    org_name: '',
    provider: '',
    site_id: '',
    site_name: 'Branch A',
    node_id: '',
    source_node: 'meraki:1:d:BR',
    node_label: 'Branch A MX',
    kind: '',
    vlan: null,
    cidr: '10.10.10.5',
    name: '',
    in_vpn: null,
    ...fields,
  });
}

describe('typed source', () => {
  const filtered = { providers: ['meraki'], sources: [1], vlans: '10', name: 'data', sites: 'branch', inVpn: '1' as const };

  it('sends the source and its picked owner, and no source filter, with a destination', () => {
    const built = buildReachabilityQuery({
      ...emptyForm(),
      ...filtered,
      source: ' 10.10.10.0/24 ',
      sourceOrgRef: 1,
      sourceNodeId: 'd:BR',
      destination: '10.0.10.20',
      destinationOrgRef: 2,
      destinationNodeId: 'd:HUB',
    });
    expect(built).toEqual({
      query: {
        source: '10.10.10.0/24',
        source_org_ref: 1,
        source_node_id: 'd:BR',
        destination: '10.0.10.20',
        destination_org_ref: 2,
        destination_node_id: 'd:HUB',
        protocol: 'tcp',
        port: 445,
      },
    });
  });

  it('traces a typed source to every kept destination network without narrowing them', () => {
    const built = buildReachabilityQuery({ ...emptyForm(), source: '10.10.10.5', to: { ...emptyFilters(), name: 'srv' } });
    expect(built).toEqual({ query: { source: '10.10.10.5', protocol: 'tcp', port: 445, to_name: 'srv' } });
    // Every destination network: no narrowing is needed for one source.
    const wide = buildReachabilityQuery({ ...emptyForm(), source: '10.10.10.5' });
    expect('query' in wide && isMatrixQuery(wide.query)).toBe(true);
    // The destination filters are still checked.
    expect(buildReachabilityQuery({ ...emptyForm(), source: '10.10.10.5', to: { ...emptyFilters(), kinds: [] } })).toHaveProperty(
      'error',
    );
  });

  it('neither checks nor sends the source filters, and no owner without a source', () => {
    const built = buildReachabilityQuery({
      ...emptyForm(),
      ...filtered,
      vlans: 'x',
      kinds: [],
      source: '10.10.10.5',
      destination: '10.0.10.20',
    });
    expect('query' in built).toBe(true);
    if (!('query' in built)) return;
    expect(Object.keys(built.query).filter((key) => SOURCE_FILTER_KEYS.includes(key))).toEqual([]);
    expect(built.query).not.toHaveProperty('source_org_ref');

    const noSource = buildReachabilityQuery({ ...emptyForm(), sourceOrgRef: 1, sourceNodeId: 'd:BR', destination: '10.0.10.20' });
    expect('query' in noSource && Object.keys(noSource.query).filter((key) => key === 'source' || key.startsWith('source_'))).toEqual(
      [],
    );
  });

  it('still refuses no source and no destination with wide destination filters', () => {
    expect(buildReachabilityQuery({ ...emptyForm(), source: '  ' })).toEqual({ error: MATRIX_NARROW_ERROR });
    expect(isTypedSource({ source: ' ' })).toBe(false);
    expect(isTypedSource({ source: '10.0.0.1' })).toBe(true);
  });

  it('keeps each end and its owner in its own fields', () => {
    const owner = { org_ref: 2, node_id: 'd:HUB' };
    expect(endPatch('source', '10.0.0.0/24', owner)).toEqual({ source: '10.0.0.0/24', sourceOrgRef: 2, sourceNodeId: 'd:HUB' });
    expect(endPatch('destination', '10.0.0.1')).toEqual({
      destination: '10.0.0.1',
      destinationOrgRef: undefined,
      destinationNodeId: undefined,
    });
    expect(endOwnerPatch('destination', owner)).toEqual({ destinationOrgRef: 2, destinationNodeId: 'd:HUB' });
  });

  it('places each typed end that one subnet holds at its owner', () => {
    const subnet = (cidr: string, orgRef: number, nodeId: string): MerakiSubnet => ({
      org_ref: orgRef, provider: 'meraki', cidr, name: 'VLAN', kind: 'vlan', site_id: 'S', site_name: 'Site',
      node_id: nodeId, in_vpn: true,
    });
    const subnets = [subnet('10.1.0.0/24', 1, 'd:A'), subnet('10.2.0.0/24', 1, 'd:B'), subnet('10.2.0.0/24', 2, 'd:C')];
    const placed = withSingleOwners({ ...emptyForm(), source: '10.1.0.5', destination: '10.2.0.9' }, subnets);
    expect(placed).toMatchObject({ sourceOrgRef: 1, sourceNodeId: 'd:A' });
    // Two subnets hold the destination: the user picks one.
    expect(placed.destinationOrgRef).toBeUndefined();
    // An owner already picked is kept.
    const kept = withSingleOwners({ ...emptyForm(), source: '10.1.0.5', sourceOrgRef: 7, sourceNodeId: 'd:Z' }, subnets);
    expect(kept).toMatchObject({ sourceOrgRef: 7, sourceNodeId: 'd:Z' });
  });

  it('traces a typed row again from its source node', () => {
    const report = {
      mode: 'one',
      source: { address: '10.10.10.5', node: 'meraki:1:d:BR', label: 'Branch A MX', site: 'Branch A' },
      destination: { address: '10.0.10.20', node: 'meraki:1:d:HUB', label: 'Hub MX', site: 'Hub' },
      traffic: 'tcp/445',
    } as ReachabilityReport;
    const query = { source: '10.10.10.5', destination: '10.0.10.20', protocol: 'tcp', port: 445 };
    expect(rowTraceQuery(typedRow({}), report, query)).toEqual({
      source: '10.10.10.5',
      destination: '10.0.10.20',
      source_node: 'meraki:1:d:BR',
      destination_node: 'meraki:1:d:HUB',
      protocol: 'tcp',
      port: 445,
    });
  });

  it('rolls a row with no site or source up under its node label, else No site', () => {
    const rows = [
      typedRow({ site_name: '', dst_site_name: '', dst_org_name: '', dst_node_label: 'Hub MX' }),
      typedRow({ site_name: '', node_label: '', dst_site_name: '', dst_org_name: '', dst_node_label: '' }),
    ];
    expect(siteRollup(rows).map((r) => r.site)).toEqual(['Branch A MX', 'No site']);
    expect(pairRollup(rows).map((r) => [r.source, r.destination])).toEqual([
      ['Branch A MX', 'Hub MX'],
      ['No site', 'No site'],
    ]);
  });
});

describe('list networks', () => {
  it('sends only the source filters and list, leaving the default kinds out', () => {
    const built = buildListQuery({
      ...emptyForm(),
      destination: '10.0.10.20',
      traffic: 'udp 53',
      providers: ['meraki'],
      name: 'data',
      to: { ...emptyFilters(), providers: ['aws'] },
    });
    expect(built).toEqual({
      query: {
        list: '1',
        protocol: '',
        sources: undefined,
        providers: 'meraki',
        kinds: undefined,
        vlans: undefined,
        name: 'data',
        exclude: undefined,
        sites: undefined,
        within: undefined,
        in_vpn: undefined,
      },
    });
    if (!('query' in built)) return;
    expect(isListQuery(built.query)).toBe(true);
    expect(isMatrixQuery(built.query)).toBe(false);
    expect(buildListQuery({ ...emptyForm(), kinds: ['vlan'] })).toMatchObject({ query: { kinds: 'vlan' } });
  });

  it('refuses a typed source and bad source filters', () => {
    expect(buildListQuery({ ...emptyForm(), source: '10.0.0.1' })).toEqual({ error: LIST_TYPED_SOURCE_ERROR });
    expect(buildListQuery({ ...emptyForm(), vlans: 'x' })).toHaveProperty('error');
    expect(buildListQuery({ ...emptyForm(), kinds: [] })).toHaveProperty('error');
  });

  it('rolls listed networks up per site, counting no verdicts', () => {
    const network = (fields: Partial<NetworkRow>): NetworkRow => {
      const { org_ref, org_name, provider, site_id, site_name, node_id, source_node, node_label, kind, vlan, cidr, name, in_vpn } =
        row(fields);
      return { org_ref, org_name, provider, site_id, site_name, node_id, source_node, node_label, kind, vlan, cidr, name, in_vpn };
    };
    const rows = [network({}), network({ cidr: '10.10.30.0/24' }), network({ site_name: 'Branch B' })];
    expect(rows.some(isTraceRow)).toBe(false);
    expect(siteRollup(rows)).toEqual([
      { site: 'Branch A', checked: 2, counts: { allowed: 0, blocked: 0, unreachable: 0, partial: 0, unknown: 0 } },
      { site: 'Branch B', checked: 1, counts: { allowed: 0, blocked: 0, unreachable: 0, partial: 0, unknown: 0 } },
    ]);
  });
});
