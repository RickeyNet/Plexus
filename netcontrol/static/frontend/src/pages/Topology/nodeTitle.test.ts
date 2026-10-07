import { describe, expect, it } from 'vitest';

import type { TopologyInstanceRef, TopologyNode } from '@/api/topology';

import { nodeSearchText, nodeTitle } from './helpers';

const INSTANCE: TopologyInstanceRef = {
  provider: 'aws',
  id: 'i-0123456789abcdef0',
  subnet: 'subnet-0aa11 (10.20.1.0/24)',
  vpc: 'prod-vpc',
  org_ref: 7,
  node_id: 'aws:i-0123456789abcdef0',
};

/** An inventory host whose primary reference is a Cato socket, also an EC2 instance. */
const INVENTORY_NODE: TopologyNode = {
  id: 12,
  label: 'vsocket-east',
  ip: '10.20.1.5',
  device_type: 'cisco_ios',
  in_inventory: true,
  group_name: 'Cloud',
  meraki: {
    org_ref: 3,
    node_id: 'cato:site-1',
    site_id: 'site-1',
    site_name: 'AWS East',
    kind: 'appliance',
    status: 'online',
    provider: 'cato',
  },
  also_providers: ['aws'],
  instance: INSTANCE,
};

/** An AWS instance known only to the AWS integration. */
const AWS_NODE: TopologyNode = {
  id: 'meraki:7:aws:i-0123456789abcdef0',
  label: 'web-1',
  ip: '10.20.1.9',
  in_inventory: false,
  source: 'meraki',
  meraki: {
    org_ref: 7,
    node_id: 'aws:i-0123456789abcdef0',
    site_id: 'vpc-1',
    site_name: 'prod-vpc',
    kind: 'server',
    status: 'running',
    provider: 'aws',
    instance_id: 'i-0123456789abcdef0',
    subnet: 'subnet-0aa11 (10.20.1.0/24)',
  },
  instance: INSTANCE,
};

describe('nodeTitle', () => {
  it('shows the instance, subnet and VPC of an inventory host', () => {
    const title = nodeTitle(INVENTORY_NODE);
    expect(title).toContain('\nInstance: i-0123456789abcdef0 · subnet-0aa11 (10.20.1.0/24)');
    expect(title).toContain('\nVPC: prod-vpc');
    expect(title.endsWith('\nDrag to move · Right-click to unpin')).toBe(true);
  });

  it('shows the instance of an integration-only AWS node without repeating the VPC', () => {
    const title = nodeTitle(AWS_NODE);
    expect(title).toContain('\nSite: prod-vpc');
    expect(title).toContain('\nInstance: i-0123456789abcdef0 · subnet-0aa11 (10.20.1.0/24)');
    expect(title).not.toContain('VPC:');
    expect(title.endsWith('\nDrag to move · Right-click to unpin')).toBe(true);
  });

  it('leaves the subnet off when it is unknown', () => {
    const title = nodeTitle({ ...INVENTORY_NODE, instance: { ...INSTANCE, subnet: '' } });
    expect(title).toContain('\nInstance: i-0123456789abcdef0\n');
  });

  it('adds nothing for a node without an instance', () => {
    const title = nodeTitle({ ...INVENTORY_NODE, instance: undefined });
    expect(title).not.toContain('Instance:');
    expect(title).not.toContain('VPC:');
  });
});

describe('nodeSearchText', () => {
  it('includes the instance ID of a node', () => {
    expect(nodeSearchText(INVENTORY_NODE)).toContain('i-0123456789abcdef0');
  });

  it("includes the instance ID of the node's AWS reference", () => {
    expect(nodeSearchText({ ...AWS_NODE, instance: undefined })).toContain('i-0123456789abcdef0');
  });
});
