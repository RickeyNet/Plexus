import { describe, expect, it } from 'vitest';

import type { TopologyInstanceRef, TopologyNode } from '@/api/topology';

import { DEVICE_ROLES, merakiNodeShape, nodeIconUrl, nodeKindIconUrl, nodeKindLabel, nodeSearchText, nodeTitle } from './helpers';

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

  it('names the integration of an Appgate SDP node', () => {
    const title = nodeTitle({
      id: 'meraki:9:a:gw-1',
      label: 'appgate-gw-hq-1',
      ip: '10.160.1.21',
      in_inventory: false,
      source: 'meraki',
      meraki: {
        org_ref: 9,
        node_id: 'a:gw-1',
        site_id: 'site-hq',
        site_name: 'HQ Data Center',
        kind: 'appliance',
        status: 'online',
        provider: 'appgate',
      },
    });
    expect(title).toContain('\nAppgate SDP appliance · online');
    expect(title).toContain('\nSite: HQ Data Center');
  });

  it('names the integration of an OPNsense node', () => {
    const title = nodeTitle({
      id: 'meraki:12:d:fw1',
      label: 'branch-fw-1',
      ip: '192.0.2.1',
      in_inventory: false,
      source: 'meraki',
      meraki: {
        org_ref: 12,
        node_id: 'd:fw1',
        site_id: 'site-branch',
        site_name: 'Branch Office',
        kind: 'appliance',
        status: 'online',
        provider: 'opnsense',
      },
    });
    expect(title).toContain('\nOPNsense appliance · online');
    expect(title).toContain('\nSite: Branch Office');
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

/** An OpenVPN server instance on an OPNsense firewall. */
const VPN_SERVER_NODE: TopologyNode = {
  id: 'meraki:12:ovpn:server:1',
  label: 'Road warrior',
  ip: '',
  device_type: 'opnsense',
  device_category: 'vpn_server',
  in_inventory: false,
  source: 'meraki',
  meraki: {
    org_ref: 12,
    node_id: 'ovpn:server:1',
    site_id: 'site-branch',
    site_name: 'Branch Office',
    kind: 'vpn_server',
    status: 'online',
    provider: 'opnsense',
  },
};

describe('vpn_server nodes', () => {
  it('labels the kind "VPN server" and leaves other kinds as they are', () => {
    expect(nodeKindLabel('vpn_server')).toBe('VPN server');
    expect(nodeKindLabel('vpn_peer')).toBe('VPN peer');
    expect(nodeKindLabel('appliance')).toBe('appliance');
    expect(nodeKindLabel(undefined)).toBe('');
  });

  it('names the kind in the tooltip', () => {
    expect(nodeTitle(VPN_SERVER_NODE)).toContain('\nOPNsense VPN server · online');
  });

  it('draws a VPN server with the server icon, and other integration kinds without one', () => {
    expect(nodeKindIconUrl('vpn_server')).toBe('/static/img/topo/server.svg');
    expect(nodeIconUrl(VPN_SERVER_NODE)).toBe('/static/img/topo/server.svg');
    expect(nodeKindIconUrl('vpn_peer')).toBeUndefined();
    const peer = { ...VPN_SERVER_NODE, device_category: 'vpn_peer', meraki: { ...VPN_SERVER_NODE.meraki!, kind: 'vpn_peer' } };
    expect(nodeIconUrl(peer)).toBeUndefined();
    expect(merakiNodeShape(peer)).toBe('hexagon');
  });

  it('is found by searching for its kind', () => {
    expect(nodeSearchText(VPN_SERVER_NODE)).toContain('vpn server');
    expect(nodeSearchText(AWS_NODE)).not.toContain('server');
  });
});

describe('a source device that is an inventory host', () => {
  // A Meraki switch added to the inventory as an ICMP-only host: no role of its own.
  const HOST: TopologyNode = {
    id: 31,
    label: 'branch-sw1',
    ip: '192.0.2.31',
    device_type: 'icmp_only',
    device_category: '',
    in_inventory: true,
    source_category: 'switch',
  };

  it('keeps the icon of the role its source gives it', () => {
    expect(nodeIconUrl(HOST)).toBe('/static/img/topo/switch.svg');
    // A host no source knows is drawn by its device type alone.
    expect(nodeIconUrl({ ...HOST, source_category: undefined })).toBeUndefined();
  });

  it('is drawn with its own role, or the one its device type implies, first', () => {
    expect(nodeIconUrl({ ...HOST, device_category: 'router' })).toBe('/static/img/topo/router.svg');
    expect(nodeIconUrl({ ...HOST, device_type: 'cisco_asa' })).toBe('/static/img/topo/firewall.svg');
  });
});

describe('UPS hosts', () => {
  const UPS_NODE: TopologyNode = { id: 40, label: 'ups-a1', ip: '192.0.2.40', device_type: 'apc_ups', in_inventory: true };

  it('draws a UPS with the UPS icon, from its role or else its device type', () => {
    expect(nodeIconUrl({ ...UPS_NODE, device_category: 'ups' })).toBe('/static/img/topo/ups.svg');
    expect(nodeIconUrl(UPS_NODE)).toBe('/static/img/topo/ups.svg');
    // A role someone set wins over the device type.
    expect(nodeIconUrl({ ...UPS_NODE, device_category: 'server' })).toBe('/static/img/topo/server.svg');
  });

  it('offers UPS as a role', () => {
    expect(DEVICE_ROLES).toContain('ups');
  });
});
