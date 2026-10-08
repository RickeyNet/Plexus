import { describe, expect, it } from 'vitest';

import {
  discoverOutcome,
  liveMissingDependencies,
  liveUnavailableReason,
  pullOutcome,
  topologyConnectionLabel,
  topologyResourceTypeLabel,
} from './helpers';

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

describe('liveUnavailableReason', () => {
  const providers = [
    { id: 'aws', live_supported: false, missing_dependencies: ['boto3'] },
    { id: 'azure', live_supported: false, missing_dependencies: ['azure-identity', 'azure-mgmt-network'] },
    { id: 'gcp', live_supported: true, missing_dependencies: [] },
  ];

  it('names the missing package and how to install it', () => {
    expect(liveUnavailableReason('aws', providers)).toBe(
      'Live reads need boto3 on the Plexus server. Install with: pip install -r requirements-cloud.txt',
    );
  });

  it('joins several missing packages', () => {
    expect(liveUnavailableReason('AZURE', providers)).toBe(
      'Live reads need azure-identity, azure-mgmt-network on the Plexus server. Install with: pip install -r requirements-cloud.txt',
    );
    expect(liveMissingDependencies('azure', providers)).toEqual(['azure-identity', 'azure-mgmt-network']);
  });

  it('does not block when live reads are supported', () => {
    expect(liveUnavailableReason('gcp', providers)).toBeNull();
    expect(liveMissingDependencies('gcp', providers)).toEqual([]);
  });

  it('does not block an unknown provider or before capabilities load', () => {
    expect(liveUnavailableReason('oci', providers)).toBeNull();
    expect(liveUnavailableReason('aws', [])).toBeNull();
    expect(liveUnavailableReason('aws', [{ id: 'aws' }])).toBeNull();
  });

  it('still explains when no package is named', () => {
    expect(liveUnavailableReason('aws', [{ id: 'aws', live_supported: false }])).toBe(
      'Live reads are not available on the Plexus server. Install with: pip install -r requirements-cloud.txt',
    );
  });
});

describe('discoverOutcome', () => {
  const summary = { ok: true, resources: 42, connections: 61, hybrid_links: 0, policy_rules: 3 };

  it('states what was found and where', () => {
    expect(discoverOutcome('Test AWS', { ok: true, summary }, 'us-east-1, eu-west-1')).toEqual({
      kind: 'success',
      text: 'Test AWS: discovery completed, 42 resources and 61 connections (us-east-1, eu-west-1)',
    });
    expect(discoverOutcome('Prod Azure', { ok: true, summary: { resources: 1, connections: 1 } }, null)).toEqual({
      kind: 'success',
      text: 'Prod Azure: discovery completed, 1 resource and 1 connection',
    });
    expect(discoverOutcome('Big', { ok: true, summary: { resources: 1200 } }, null).text).toBe(
      `Big: discovery completed, ${(1200).toLocaleString()} resources and 0 connections`,
    );
  });

  it('reports a run that found nothing as an error, naming the regions', () => {
    expect(discoverOutcome('Test AWS', { ok: true, summary: { resources: 0, connections: 0 } }, 'us-east-1')).toEqual({
      kind: 'error',
      text: "Test AWS: discovery completed but found no resources in us-east-1. Check the region scope and the credentials' permissions.",
    });
  });

  it('reports a run that found nothing without regions for providers that have none', () => {
    expect(discoverOutcome('Prod GCP', { ok: true, summary: { resources: 0 } }, null)).toEqual({
      kind: 'error',
      text: "Prod GCP: discovery completed but found no resources. Check the credentials' permissions.",
    });
  });

  it('falls back to the server message without a summary', () => {
    expect(discoverOutcome('Test AWS', { ok: true, message: 'Live provider discovery snapshot refreshed' }, 'us-east-1')).toEqual({
      kind: 'success',
      text: 'Test AWS: Live provider discovery snapshot refreshed',
    });
    expect(discoverOutcome('Test AWS', { ok: true, summary: null }, null)).toEqual({
      kind: 'success',
      text: 'Test AWS: Discovery completed',
    });
  });
});
