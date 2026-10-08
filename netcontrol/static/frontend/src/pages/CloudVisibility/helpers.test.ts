import { describe, expect, it } from 'vitest';

import { pullOutcome, topologyConnectionLabel, topologyResourceTypeLabel } from './helpers';

describe('pullOutcome', () => {
  it('reports what was ingested', () => {
    expect(pullOutcome('Flow pull', { ok: true, ingested: 1200 })).toEqual({
      kind: 'success',
      text: `Flow pull complete: ${(1200).toLocaleString()} ingested`,
    });
    expect(pullOutcome('Prod: VPC Flow Logs pull', { total_ingested: 5 }, (n) => `Prod: ${n} VPC Flow Logs records ingested`)).toEqual({
      kind: 'success',
      text: 'Prod: 5 VPC Flow Logs records ingested',
    });
  });

  it('treats ok: false as an error', () => {
    expect(pullOutcome('Traffic pull', { ok: false, ingested: 0 })).toEqual({
      kind: 'error',
      text: 'Traffic pull finished with unknown error(s); ingested 0. ',
    });
  });

  it('treats a list of errors as an error, naming the first three', () => {
    const outcome = pullOutcome('Flow pull', { ok: true, ingested: 3, errors: ['a', 'b', 'c', 'd'] }, () => 'unused');
    expect(outcome).toEqual({ kind: 'error', text: 'Flow pull finished with 4 error(s); ingested 3. a | b | c' });
  });
});

describe('topologyResourceTypeLabel', () => {
  it('uses the provider name of the construct', () => {
    expect(topologyResourceTypeLabel('vpc', 'gcp')).toBe('VPC network');
    expect(topologyResourceTypeLabel('vpc', 'aws')).toBe('VPC');
    expect(topologyResourceTypeLabel('instance', 'azure')).toBe('Virtual machine');
    expect(topologyResourceTypeLabel('instance', 'aws')).toBe('EC2 instance');
    expect(topologyResourceTypeLabel('instance', 'gcp')).toBe('Compute Engine instance');
    expect(topologyResourceTypeLabel('vm', 'azure')).toBe('Virtual machine');
    expect(topologyResourceTypeLabel('network_security_group', 'azure')).toBe('Network security group');
    expect(topologyResourceTypeLabel('collection_warning', 'aws')).toBe('Collection warning');
  });

  it('falls back to the type in words', () => {
    expect(topologyResourceTypeLabel('private_link_service', 'azure')).toBe('Private Link Service');
  });
});

describe('topologyConnectionLabel', () => {
  it('names connections the way the provider does', () => {
    expect(topologyConnectionLabel('vpn', 'aws')).toBe('VPN');
    expect(topologyConnectionLabel('vnet_peering', 'azure')).toBe('VNet peering');
    expect(topologyConnectionLabel('peering', 'azure')).toBe('VNet peering');
    expect(topologyConnectionLabel('vpn_tunnel', 'gcp')).toBe('HA VPN tunnel');
    expect(topologyConnectionLabel('vpn_tunnel', 'aws')).toBe('VPN tunnel');
  });

  it('says what a route table is attached to', () => {
    expect(topologyConnectionLabel('route_table_association', 'azure', { subnet_name: 'web' })).toBe('Attached subnet');
    expect(topologyConnectionLabel('route_table_association', 'aws', {})).toBe('Attached network');
    expect(topologyConnectionLabel('route_table_association', 'aws')).toBe('Attached network');
  });
});
