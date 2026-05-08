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

export interface SyncReadiness {
  flowReady: boolean;
  trafficReady: boolean;
  flowMissing: string[];
  trafficMissing: string[];
}

export function computeSyncReadiness(account: {
  provider?: string;
  auth_config?: unknown;
}): SyncReadiness {
  const provider = String(account.provider ?? '').toLowerCase();
  const raw = account.auth_config;
  let auth: Record<string, unknown> = {};
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) auth = raw as Record<string, unknown>;
  else if (typeof raw === 'string' && raw.trim()) {
    try {
      auth = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      /* ignore */
    }
  }

  const hasNonEmptyList = (v: unknown): boolean => {
    if (Array.isArray(v)) return v.some((i) => String(i ?? '').trim());
    if (typeof v === 'string') {
      const t = v.trim();
      if (!t) return false;
      if (t.startsWith('[')) {
        try {
          const parsed = JSON.parse(t);
          return Array.isArray(parsed) && parsed.some((i) => String(i ?? '').trim());
        } catch {
          return false;
        }
      }
      return t.split(',').some((i) => i.trim());
    }
    return false;
  };

  const flowMissing: string[] = [];
  const trafficMissing: string[] = [];
  if (provider === 'aws') {
    if (!String(auth.log_group_name ?? '').trim()) flowMissing.push('log_group_name');
    if (!hasNonEmptyList(auth.resource_ids)) trafficMissing.push('resource_ids');
  } else if (provider === 'azure') {
    if (!String(auth.storage_account_name ?? '').trim()) flowMissing.push('storage_account_name');
    if (!String(auth.container_name ?? '').trim()) flowMissing.push('container_name');
    if (!hasNonEmptyList(auth.resource_ids)) trafficMissing.push('resource_ids');
  } else if (provider === 'gcp') {
    if (!String(auth.project_id ?? '').trim()) flowMissing.push('project_id');
    if (!String(auth.project_id ?? '').trim()) trafficMissing.push('project_id');
  }
  return {
    flowReady: flowMissing.length === 0,
    trafficReady: trafficMissing.length === 0,
    flowMissing,
    trafficMissing,
  };
}

export function authHintContent(provider: string): { flow: string; traffic: string; example: Record<string, unknown> } {
  const n = provider.toLowerCase();
  if (n === 'aws') {
    return {
      flow: 'Flow sync requires log_group_name for VPC Flow Logs in CloudWatch Logs.',
      traffic: 'Traffic sync requires resource_ids and optionally metric_names, metric_namespace, and resource_dimension_name.',
      example: {
        log_group_name: '/aws/vpc/flow-logs',
        resource_ids: ['i-1234567890abcdef0'],
        metric_names: ['NetworkIn', 'NetworkOut'],
        metric_namespace: 'AWS/EC2',
        resource_dimension_name: 'InstanceId',
      },
    };
  }
  if (n === 'azure') {
    return {
      flow: 'Flow sync requires storage_account_name and container_name for NSG flow log blobs.',
      traffic: 'Traffic sync requires resource_ids and can use metric_names plus service principal or DefaultAzureCredential settings.',
      example: {
        storage_account_name: 'mystorageacct',
        container_name: 'insights-logs-networksecuritygroupflowevent',
        resource_ids: ['/subscriptions/.../resourceGroups/.../providers/Microsoft.Network/networkInterfaces/nic-1'],
        metric_names: ['BytesIn', 'BytesOut'],
      },
    };
  }
  if (n === 'gcp') {
    return {
      flow: 'Flow sync requires project_id for Cloud Logging queries.',
      traffic: 'Traffic sync requires project_id and can optionally override metric_types or provide service_account_json.',
      example: {
        project_id: 'my-gcp-project',
        metric_types: [
          'compute.googleapis.com/instance/network/received_bytes_count',
          'compute.googleapis.com/instance/network/sent_bytes_count',
        ],
      },
    };
  }
  return {
    flow: 'Choose a provider to see required sync auth keys.',
    traffic: 'Choose a provider to see traffic metric sync requirements.',
    example: {},
  };
}
