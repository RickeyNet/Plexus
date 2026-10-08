import { describe, expect, it } from 'vitest';

import type { MerakiSubnet, PathDirection, PathHop } from '@/api/meraki';

import { connectPicks, type PathPick } from './paths';
import {
  hopTitle,
  itemWhere,
  legKey,
  mergeHighlights,
  pathTraceQuery,
  reverseTraceQuery,
  stageLabel,
  statusMark,
  traceEnds,
  traceHighlight,
  traceRoute,
  uncheckedTraceNote,
  verdictLabel,
} from './pathTrace';

function subnet(cidr: string, node: string, site: string): MerakiSubnet {
  return { org_ref: 1, provider: 'meraki', cidr, name: 'VLAN 10 Data', kind: 'vlan', site_id: site, site_name: site, node_id: node, in_vpn: true };
}

function pick(s: MerakiSubnet, address?: string): PathPick {
  return { key: `s:${address ?? s.cidr}:${s.node_id}`, node: s.node_id, label: `${address ?? s.cidr} · ${s.site_name}`, subnet: s, address };
}

function hop(part: Partial<PathHop>): PathHop {
  return { node: null, edge: null, label: '', site: '', provider: 'meraki', in: '', out: '', status: 'ok', items: [], ...part };
}

const branch = subnet('10.1.10.0/24', 'mx-a', 'Branch 01');
const hub = subnet('10.0.10.0/24', 'hub', 'Hub 01');
const mx: PathPick = { key: 'n:mx-a', node: 'mx-a', label: 'Branch 01 MX' };

describe('path trace query', () => {
  it('traces two subnets or addresses, with the typed address and the owners', () => {
    expect(pathTraceQuery(pick(branch, '10.1.10.5'), pick(hub), { protocol: 'tcp', port: 443 })).toEqual({
      source: '10.1.10.5',
      destination: '10.0.10.0/24',
      source_node: 'mx-a',
      destination_node: 'hub',
      protocol: 'tcp',
      port: 443,
    });
    // Any traffic: no protocol, no port.
    expect(pathTraceQuery(pick(branch), pick(hub), { protocol: '' })).toMatchObject({ protocol: '', port: undefined });
  });

  it('does not trace a device or site pick', () => {
    expect(pathTraceQuery(mx, pick(hub), { protocol: '' })).toBeNull();
    expect(pathTraceQuery(pick(hub), mx, { protocol: '' })).toBeNull();
  });

  it('reverses the ends and keeps the traffic', () => {
    const forward = pathTraceQuery(pick(branch, '10.1.10.5'), pick(hub, '10.0.10.20'), { protocol: 'udp', port: 53 })!;
    expect(reverseTraceQuery(forward)).toEqual({
      source: '10.0.10.20',
      destination: '10.1.10.5',
      source_node: 'hub',
      destination_node: 'mx-a',
      protocol: 'udp',
      port: 53,
    });
    expect(traceEnds(reverseTraceQuery(forward))).toBe('10.0.10.20 → 10.1.10.5');
  });

  it('says which end to add as a subnet', () => {
    expect(uncheckedTraceNote(pick(hub), mx)).toBe(
      'Routes, policies and NAT are checked only between two subnets or IP addresses: ' +
        'add Branch 01 MX with the subnet box instead (one of its subnets, or an IP address).',
    );
    expect(uncheckedTraceNote(mx, pick(hub))).toContain('add Branch 01 MX with the subnet box');
    // Traced legs, and legs between two devices, need no note.
    expect(uncheckedTraceNote(pick(branch), pick(hub))).toBeNull();
    expect(uncheckedTraceNote(mx, { key: 'n:hub', node: 'hub', label: 'Hub 01 MX' })).toBeNull();
  });
});

describe('path trace display', () => {
  it('names hops with their site, ingress and egress', () => {
    expect(hopTitle(hop({ node: 'hub', label: 'Hub 01 MX', site: 'Hub 01', in: 'AutoVPN from Branch 01', out: 'VLAN 20' }), 2)).toBe(
      '3. Hub 01 MX · Hub 01 · in AutoVPN from Branch 01 → out VLAN 20',
    );
    expect(hopTitle(hop({ node: 'mx-a', label: 'Branch 01 MX', site: 'Branch 01', in: 'VLAN 10' }), 0)).toBe('1. Branch 01 MX · Branch 01 · in VLAN 10');
    expect(hopTitle(hop({ label: 'Internet', provider: 'internet', out: 'wan1' }), 1)).toBe('2. Internet · out wan1');
    expect(hopTitle(hop({ label: 'Prod VPC', site: 'Prod VPC' }), 4)).toBe('5. Prod VPC');
  });

  it('labels stages, statuses and verdicts', () => {
    expect(['policy', 'acl', 'security_group', 'nat', 'route', 'link', 'note'].map(stageLabel)).toEqual([
      'Policy',
      'ACL',
      'Security group',
      'NAT',
      'Route',
      'Link',
      'Note',
    ]);
    expect(['ok', 'blocked', 'partial', 'unknown', 'info'].map((s) => statusMark(s).mark)).toEqual(['✓', '✕', '◐', '?', 'i']);
    expect(statusMark('blocked').color).toBe('var(--danger)');
    expect(statusMark('info').color).toBe('var(--text-muted, #868e96)');
    expect(['allowed', 'blocked', 'partial', 'unknown'].map((v) => verdictLabel(v).label)).toEqual([
      'Allowed',
      'Blocked',
      'Allowed in part',
      'Check incomplete',
    ]);
    expect(verdictLabel('allowed').color).toBe('var(--success, #2f9e44)');
  });

  it('lists the hops of a direction on one line, marking those not ok', () => {
    const blocked: PathDirection = {
      verdict: 'blocked',
      summary: 'Blocked at 1000 - Corp East Backup.',
      hops: [
        hop({ node: 1049, label: '1049 - Data Eng HQ' }),
        hop({ node: 1000, edge: 7, label: '1000 - AWS Corp East VMX-Large' }),
        hop({ node: 1001, edge: 8, label: '1000 - Corp East Backup', status: 'blocked' }),
      ],
    };
    expect(traceRoute(blocked)).toBe('1049 - Data Eng HQ → 1000 - AWS Corp East VMX-Large → 1000 - Corp East Backup ✕ (3 hops)');
    // The Internet pseudo hop has no node; one hop is "1 hop".
    expect(traceRoute({ verdict: 'unknown', summary: '', hops: [hop({ status: 'unknown' })] })).toBe('Internet ? (1 hop)');
    expect(
      traceRoute({ verdict: 'allowed', summary: '', hops: [hop({ node: 'mx-a', label: 'Branch 01 MX' }), hop({ label: 'Internet' }), hop({ node: 'hub' })] }),
    ).toBe('Branch 01 MX → Internet → hub (3 hops)');
    expect(traceRoute({ verdict: 'unknown', summary: '', hops: [] })).toBeNull();
    expect(traceRoute(undefined)).toBeNull();
  });

  it('shows the matching rule with the rule set', () => {
    const item = { stage: 'policy' as const, status: 'blocked' as const, where: 'Layer 3 firewall rules', text: 'Rule 2 matches.' };
    expect(itemWhere({ ...item, rule: 2 })).toBe('Layer 3 firewall rules, rule 2');
    expect(itemWhere({ ...item, rule: null })).toBe('Layer 3 firewall rules');
    expect(itemWhere(item)).toBe('Layer 3 firewall rules');
  });
});

describe('path trace on the map', () => {
  const request: PathDirection = {
    verdict: 'allowed',
    summary: '',
    hops: [
      hop({ node: 'mx-a', label: 'Branch 01 MX' }),
      hop({ node: 'hub', edge: 'vpn-a', label: 'Hub 01 MX' }),
      hop({ node: null, edge: null, label: 'Internet', provider: 'internet' }),
      hop({ node: 12, edge: 42, label: 'core-sw' }),
    ],
  };

  it('highlights the hops and the links taken into them', () => {
    const lit = traceHighlight(request);
    expect([...lit.nodeIds]).toEqual(['mx-a', 'hub', 12]);
    expect([...lit.edgeIds]).toEqual(['vpn-a', 42]);
    expect(traceHighlight(undefined).nodeIds.size).toBe(0);
  });

  it('replaces the drawn path of a traced leg, and keeps it for the others', () => {
    const edges = [
      { id: 'vpn-a', from: 'mx-a', to: 'hub', protocol: 'vpn', status: '' },
      { id: 'vpn-b', from: 'mx-b', to: 'hub', protocol: 'vpn', status: '' },
      { id: 'lan-b', from: 'mx-b', to: 'sw-b', protocol: 'lldp', status: '' },
    ];
    const far = subnet('10.2.10.0/24', 'mx-b', 'Branch 02');
    const sw: PathPick = { key: 'n:sw-b', node: 'sw-b', label: 'sw-b' };
    const picks = [pick(branch), pick(far), sw];
    const result = connectPicks(picks, edges);
    const traced = result.legs[0];
    const lit = mergeHighlights(picks, result.legs, {
      [legKey(traced)]: { nodeIds: new Set(['mx-a', 'other-hub', 'mx-b']), edgeIds: new Set(['vpn-x', 'vpn-y']) },
    });
    // The trace went over another hub; the two legs to sw-b keep their drawn paths.
    expect([...lit.nodeIds].sort()).toEqual(['hub', 'mx-a', 'mx-b', 'other-hub', 'sw-b']);
    expect([...lit.edgeIds].sort()).toEqual(['lan-b', 'vpn-a', 'vpn-b', 'vpn-x', 'vpn-y']);
    // A trace with no hops (pending, failed, not placed) keeps the drawn path.
    const plain = mergeHighlights(picks, result.legs, { [legKey(traced)]: { nodeIds: new Set(), edgeIds: new Set() } });
    expect([...plain.nodeIds].sort()).toEqual(['hub', 'mx-a', 'mx-b', 'sw-b']);
    expect([...plain.edgeIds].sort()).toEqual(['lan-b', 'vpn-a', 'vpn-b']);
  });
});
