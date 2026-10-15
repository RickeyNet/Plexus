import { describe, expect, it } from 'vitest';

import type { ReachabilityReport, ReachabilityRow } from '@/api/meraki';

import {
  buildReachabilityQuery,
  csvFileName,
  CSV_COLUMNS,
  DEFAULT_SWEEP_KINDS,
  emptyForm,
  rowsToCsv,
  rowsWithVerdict,
  rowTraceQuery,
  siteRollup,
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

  it('writes CSV with the server columns and quotes what needs it', () => {
    const lines = rowsToCsv(ROWS).split('\r\n');
    expect(lines[0]).toBe(CSV_COLUMNS.join(','));
    expect(lines[1]).toBe(
      'Acme,meraki,Branch A,VLAN 10 Data,vlan,10,10.10.10.0/24,Yes,Allowed,,,Every hop allows it: Branch A MX → Hub MX.',
    );
    expect(lines[2]).toContain(',No,Blocked,Branch A MX,"Layer 3 firewall rules: Rule 1 (deny any, ""guest"") denies it",');
    expect(lines[3]).toContain(',,10.20.10.0/24,,Check incomplete,');
    expect(lines[4]).toBe('');
  });

  it('names the CSV file after the destination and traffic', () => {
    const report = { destination: { address: '10.0.10.20' }, traffic: 'tcp/445' };
    expect(csvFileName(report)).toBe('reachability-10.0.10.20-tcp_445.csv');
    expect(csvFileName(report, '-blocked')).toBe('reachability-10.0.10.20-tcp_445-blocked.csv');
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
