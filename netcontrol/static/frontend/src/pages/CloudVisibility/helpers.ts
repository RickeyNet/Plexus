import type { CloudPullResult } from '@/api/cloud';
import { capitalize, cloudProviderTerms } from '@/lib/cloudProviderTerms';

export function providerLabel(provider?: string | null): string {
  return cloudProviderTerms(provider).label;
}

export interface PullOutcome {
  kind: 'success' | 'error';
  text: string;
}

/**
 * The message for a flow or traffic pull. A pull that answers ok: false or
 * lists errors still returns 200, so the result has to be read, not just awaited.
 */
export function pullOutcome(
  label: string,
  result: CloudPullResult | undefined,
  successText?: (ingested: string) => string,
): PullOutcome {
  const ingested = Number(result?.ingested ?? result?.total_ingested ?? 0).toLocaleString();
  const errors = Array.isArray(result?.errors) ? result.errors : [];
  if (result?.ok === false || errors.length) {
    return {
      kind: 'error',
      text: `${label} finished with ${errors.length || 'unknown'} error(s); ingested ${ingested}. ${errors.slice(0, 3).map(String).join(' | ')}`,
    };
  }
  return { kind: 'success', text: successText ? successText(ingested) : `${label} complete: ${ingested} ingested` };
}

export function formatCount(value: unknown): string {
  return Number(value ?? 0).toLocaleString();
}

export function formatBytes(value: unknown): string {
  const bytes = Number(value) || 0;
  if (bytes >= 1e12) return `${(bytes / 1e12).toFixed(2)} TB`;
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(2)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(2)} MB`;
  if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(2)} KB`;
  return `${bytes} B`;
}

export function formatMetricValue(value: unknown): string {
  const numeric = Number(value) || 0;
  if (Math.abs(numeric) >= 1000) {
    return numeric.toLocaleString(undefined, { maximumFractionDigits: 2 });
  }
  return numeric.toFixed(2);
}

export function formatTimestamp(raw: unknown): string {
  if (!raw) return '-';
  try {
    const text = String(raw);
    const iso = text.includes('T') || text.endsWith('Z') ? text : text.replace(' ', 'T') + 'Z';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return text;
    return d.toLocaleString();
  } catch {
    return String(raw);
  }
}

export function topologyLabel(value: unknown): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) return '';
  return normalized
    .split('_')
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

const CONNECTION_LABELS: Record<string, string> = {
  route_next_hop: 'Next hop',
  transit_gateway_attachment: 'Transit Gateway',
  direct_connect: 'Direct Connect',
  direct_connect_gateway: 'Direct Connect',
  direct_connect_virtual_interface: 'Direct Connect virtual interface',
  direct_connect_gateway_association: 'Direct Connect gateway association',
  internet_gateway_attachment: 'Internet gateway',
  nat_gateway_attachment: 'NAT gateway',
  customer_gateway_attachment: 'Customer gateway',
  vpn_attachment: 'VPN attachment',
  vpn: 'VPN',
  expressroute: 'ExpressRoute',
  expressroute_gateway: 'ExpressRoute',
  virtual_network_gateway_attachment: 'VNet gateway',
  ipsec: 'IPsec tunnel',
  vnet2vnet: 'VNet-to-VNet',
  vpnclient: 'Point-to-site VPN',
  gateway_connection: 'Gateway connection',
  router_attachment: 'Cloud Router',
  interconnect_attachment: 'Interconnect',
  vnet_peering: 'VNet peering',
  vpc_peering: 'VPC peering',
  security_boundary: 'Security boundary',
};

/** A connection type as the provider names it. */
export function topologyConnectionLabel(
  connectionType: string | undefined,
  provider?: string | null,
  metadata?: Record<string, unknown> | null,
): string {
  const n = String(connectionType ?? '').toLowerCase();
  const pk = String(provider ?? '').toLowerCase();
  if (n === 'route_table_association') {
    return metadata && typeof metadata === 'object' && metadata.subnet_name ? 'Attached subnet' : 'Attached network';
  }
  if (n === 'peering') return pk === 'azure' ? 'VNet peering' : pk === 'aws' || pk === 'gcp' ? 'VPC peering' : 'Peering';
  if (n === 'vpn_tunnel') return pk === 'gcp' ? 'HA VPN tunnel' : 'VPN tunnel';
  if (n === 'vpn_gateway_attachment') return pk === 'gcp' ? 'HA VPN gateway' : 'Virtual private gateway';
  return CONNECTION_LABELS[n] ?? topologyLabel(n || connectionType || 'link');
}

const RESOURCE_TYPE_LABELS: Record<string, string> = {
  vnet: 'VNet',
  subnet: 'Subnet',
  vm: 'Virtual machine',
  route_table: 'Route table',
  route_entry: 'Route entry',
  transit_gateway: 'Transit Gateway',
  transit_gateway_route_table: 'Transit Gateway route table',
  direct_connect: 'Direct Connect',
  direct_connect_gateway: 'Direct Connect gateway',
  internet_gateway: 'Internet gateway',
  nat_gateway: 'NAT gateway',
  vpn_gateway: 'Virtual private gateway',
  vpn_connection: 'Site-to-site VPN',
  customer_gateway: 'Customer gateway',
  expressroute: 'ExpressRoute',
  virtual_network_gateway: 'Virtual network gateway',
  local_network_gateway: 'Local network gateway',
  azure_firewall: 'Azure Firewall',
  cloud_router: 'Cloud Router',
  ha_vpn_gateway: 'HA VPN gateway',
  vpn_tunnel: 'VPN tunnel',
  security_group: 'Security group',
  network_acl: 'Network ACL',
  network_security_group: 'Network security group',
  firewall_rule: 'Firewall rule',
  firewall_policy: 'Firewall policy',
  public_ip: 'Public IP',
  network_interface: 'Network interface',
  collection_warning: 'Collection warning',
};

/** A resource type as the provider names it. */
export function topologyResourceTypeLabel(t: string | undefined, provider?: string | null): string {
  const n = String(t ?? '').toLowerCase();
  const pk = String(provider ?? '').toLowerCase();
  if (n === 'vpc') return pk === 'gcp' ? 'VPC network' : 'VPC';
  if (n === 'instance') {
    if (pk === 'aws' || pk === 'azure' || pk === 'gcp') return capitalize(cloudProviderTerms(pk).compute);
    return 'Instance';
  }
  if (n === 'interconnect_attachment') return pk === 'gcp' ? 'Interconnect attachment' : 'Interconnect';
  if (n === 'internet_gateway' && pk === 'gcp') return 'Default internet gateway';
  return RESOURCE_TYPE_LABELS[n] ?? topologyLabel(n || t || 'resource');
}

export function isRouteResourceType(t?: string): boolean {
  const n = String(t ?? '').toLowerCase();
  return n === 'route_table' || n === 'route_entry';
}

export function isGatewayResourceType(t?: string): boolean {
  const n = String(t ?? '').toLowerCase();
  return [
    'internet_gateway',
    'nat_gateway',
    'vpn_gateway',
    'virtual_network_gateway',
    'local_network_gateway',
    'ha_vpn_gateway',
    'cloud_router',
    'expressroute',
    'direct_connect',
    'interconnect_attachment',
    'vpn_tunnel',
  ].includes(n);
}

export function isAttachmentConnection(t?: string): boolean {
  const n = String(t ?? '').toLowerCase();
  return n.includes('attachment') || n.includes('gateway') || n.includes('peering') || n.includes('route');
}

export function attachmentBucketLabel(t?: string): string {
  const n = String(t ?? '').toLowerCase();
  if (n.includes('peering')) return 'Peering';
  if (n.includes('gateway')) return 'Gateway';
  if (n.includes('attachment')) return 'Attachment';
  if (n.includes('route')) return 'Route';
  if (n.includes('vpn') || n.includes('ipsec')) return 'VPN';
  if (n.includes('security')) return 'Security';
  return topologyLabel(n || 'link');
}

export function attachmentBucketTone(label: string): string {
  if (label === 'Gateway') return 'success';
  if (label === 'Attachment') return 'info';
  if (label === 'Route') return 'secondary';
  if (label === 'VPN') return 'warning';
  if (label === 'Security') return 'danger';
  return 'info';
}

export function resourceMetadataSummary(resource?: { metadata?: unknown }): string {
  const md = (resource?.metadata && typeof resource.metadata === 'object'
    ? (resource.metadata as Record<string, unknown>)
    : {}) as Record<string, unknown>;
  const parts: string[] = [];
  if (md.resource_group) parts.push(`RG ${md.resource_group}`);
  if (md.vpc_id) parts.push(`VPC ${md.vpc_id}`);
  if (md.route_count) parts.push(`${formatCount(md.route_count)} routes`);
  if (md.association_count) parts.push(`${formatCount(md.association_count)} attachments`);
  if (md.gateway_type) parts.push(String(md.gateway_type));
  if (md.vpn_type) parts.push(String(md.vpn_type));
  if (md.bandwidth) parts.push(String(md.bandwidth));
  if (md.next_hop) parts.push(`Next hop ${md.next_hop}`);
  if (md.connectivity_type) parts.push(String(md.connectivity_type));
  return parts.length ? parts.join(' | ') : '-';
}

export function connectionMetadataSummary(connection?: { metadata?: unknown }): string {
  const md = (connection?.metadata && typeof connection.metadata === 'object'
    ? (connection.metadata as Record<string, unknown>)
    : {}) as Record<string, unknown>;
  const parts: string[] = [];
  if (md.destination) parts.push(String(md.destination));
  if (md.subnet_name) parts.push(`Subnet ${md.subnet_name}`);
  if (md.origin) parts.push(`Origin ${md.origin}`);
  if (md.peering_name) parts.push(`Peering ${md.peering_name}`);
  if (md.connection_status) parts.push(`Status ${md.connection_status}`);
  return parts.length ? parts.join(' | ') : '-';
}
