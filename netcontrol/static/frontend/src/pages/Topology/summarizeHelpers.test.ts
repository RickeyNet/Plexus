import { describe, expect, it } from 'vitest';

import type { SummarizeOverlap, SummarizeReport, SummarizeRoute } from '@/api/meraki';

import {
  addressCount,
  buildSummarizeRequest,
  emptySummarizeForm,
  notMerakiForm,
  overlapText,
  relationLabel,
  routeSize,
  summaryHeading,
} from './summarizeHelpers';
import { DEFAULT_SWEEP_KINDS, SWEEP_KINDS, SWEEP_PROVIDERS } from './sweep';

describe('buildSummarizeRequest', () => {
  it('sends the addresses, the numbers and the filters, leaving the default kinds out', () => {
    const built = buildSummarizeRequest({
      ...emptySummarizeForm(),
      addresses: ' 10.1.1.5\n10.1.1.6 ',
      prefix: ' 24 ',
      maxRoutes: '3',
      providers: ['cato', 'azure'],
      overlaps: '10.0.0.0/8',
    });
    expect(built).toEqual({
      request: {
        addresses: '10.1.1.5\n10.1.1.6',
        prefix: 24,
        max_routes: 3,
        sources: undefined,
        providers: 'cato,azure',
        kinds: undefined,
        vlans: undefined,
        name: undefined,
        exclude: undefined,
        sites: undefined,
        within: undefined,
        overlaps: '10.0.0.0/8',
        in_vpn: undefined,
      },
    });
  });

  it('sends empty numbers as null: exact, no limit', () => {
    expect(buildSummarizeRequest({ ...emptySummarizeForm(), addresses: '10.0.0.1' })).toMatchObject({
      request: { prefix: null, max_routes: null },
    });
  });

  it('refuses a form that cannot be sent', () => {
    const form = { ...emptySummarizeForm(), addresses: '10.0.0.1' };
    expect(buildSummarizeRequest({ ...form, addresses: '  ' })).toHaveProperty('error');
    expect(buildSummarizeRequest({ ...form, prefix: '129' })).toHaveProperty('error');
    expect(buildSummarizeRequest({ ...form, prefix: '2.5' })).toHaveProperty('error');
    expect(buildSummarizeRequest({ ...form, maxRoutes: '0' })).toHaveProperty('error');
    expect(buildSummarizeRequest({ ...form, vlans: 'x' })).toHaveProperty('error');
    expect(buildSummarizeRequest({ ...form, kinds: [] })).toHaveProperty('error');
  });
});

describe('notMerakiForm', () => {
  it('ticks every provider but Meraki and every kind, keeping the rest of the form', () => {
    const form = { ...emptySummarizeForm(), addresses: '10.0.0.1', providers: ['meraki'] };
    const next = notMerakiForm(form, [...SWEEP_PROVIDERS, 'inventory']);
    expect(next.providers).toEqual(['cato', 'fmc', 'panorama', 'appgate', 'aws', 'azure', 'gcp', 'inventory']);
    expect(next.kinds).toEqual(SWEEP_KINDS.map((k) => k.key));
    expect(next.addresses).toBe('10.0.0.1');
    expect(emptySummarizeForm().kinds).toEqual(DEFAULT_SWEEP_KINDS);
  });
});

function overlap(fields: Partial<SummarizeOverlap>): SummarizeOverlap {
  return {
    org_ref: 2, org_name: 'Cato', provider: 'cato', site_id: 'S1', site_name: 'Branch C', node_id: 's:1',
    source_node: null, node_label: '', kind: 'range', vlan: null, cidr: '10.64.10.0/24', name: 'Office',
    in_vpn: null, relation: 'inside', ...fields,
  };
}

function route(fields: Partial<SummarizeRoute>): SummarizeRoute {
  return {
    cidr: '10.64.0.0/16', version: 4, prefixlen: 16, addresses: 65536, inputs: [], input_count: 0,
    input_addresses: 0, overlaps: [], ...fields,
  };
}

describe('route text', () => {
  it('names each overlapping network and its relation', () => {
    expect(overlapText(overlap({}))).toBe('Cato · Branch C · Office (10.64.10.0/24) inside the route');
    expect(overlapText(overlap({ provider: '', site_name: '', name: '', relation: 'contains' }))).toBe(
      '(10.64.10.0/24) contains the route',
    );
    expect(relationLabel('equal')).toBe('equal');
    expect(relationLabel('overlaps')).toBe('overlaps');
  });

  it('counts addresses, an IPv6 route as a power of two', () => {
    expect(routeSize(route({}))).toBe('65,536');
    expect(routeSize(route({ cidr: '2001:db8::/32', version: 6, prefixlen: 32, addresses: 2 ** 96 }))).toBe('2^96');
    expect(addressCount(257)).toBe('257');
    expect(addressCount(2 ** 64)).toMatch(/^≈1\.84e\+19$/);
  });

  it('heads the results with the counts', () => {
    const report = { route_count: 2, input_count: 120, unique_count: 118 } as SummarizeReport;
    expect(summaryHeading(report)).toBe('2 routes cover 120 addresses (118 unique)');
    expect(summaryHeading({ ...report, route_count: 1, input_count: 1, unique_count: 1 })).toBe(
      '1 route covers 1 address (1 unique)',
    );
  });
});
