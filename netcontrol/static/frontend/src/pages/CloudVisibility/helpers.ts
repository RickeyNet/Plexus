export function providerLabel(provider?: string | null): string {
  const p = String(provider ?? '').toLowerCase();
  if (p === 'aws') return 'AWS';
  if (p === 'azure') return 'Azure';
  if (p === 'gcp') return 'GCP';
  return provider ?? '';
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
