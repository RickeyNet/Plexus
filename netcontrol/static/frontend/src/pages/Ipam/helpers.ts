import type { IpamSubnet } from '@/api/ipam';

export function formatSubnetPreview(item: IpamSubnet): string {
  const parts: string[] = [];
  const hosts = Array.isArray(item.hostnames_preview) ? item.hostnames_preview : [];
  const cloud = Array.isArray(item.cloud_resource_names_preview)
    ? item.cloud_resource_names_preview
    : [];
  const external = Array.isArray(item.external_source_names_preview)
    ? item.external_source_names_preview
    : [];
  const available = Array.isArray(item.available_preview) ? item.available_preview : [];
  if (hosts.length) {
    parts.push(
      `Hosts: ${hosts.join(', ')}${item.host_preview_truncated ? ` +${item.host_preview_truncated}` : ''}`,
    );
  }
  if (cloud.length) {
    parts.push(
      `Cloud: ${cloud.join(', ')}${item.cloud_preview_truncated ? ` +${item.cloud_preview_truncated}` : ''}`,
    );
  }
  if (external.length) {
    parts.push(
      `External: ${external.join(', ')}${item.external_source_preview_truncated ? ` +${item.external_source_preview_truncated}` : ''}`,
    );
  }
  if (available.length) {
    parts.push(`Available: ${available.join(', ')}`);
  }
  return parts.join(' | ') || 'No preview';
}

export function driftLabel(driftType: string): string {
  switch (driftType) {
    case 'missing_in_ipam':
      return 'Missing in IPAM';
    case 'missing_in_plexus':
      return 'Missing in Plexus';
    case 'hostname_mismatch':
      return 'Hostname mismatch';
    case 'status_mismatch':
      return 'Status mismatch';
    default:
      return driftType || '';
  }
}

export function driftBadgeClass(driftType: string): string {
  switch (driftType) {
    case 'missing_in_ipam':
      return 'badge-warning';
    case 'missing_in_plexus':
      return 'badge-danger';
    case 'hostname_mismatch':
      return 'badge-warning';
    default:
      return 'badge-secondary';
  }
}

export function statusBadgeClass(status: string | undefined): string {
  if (status === 'success') return 'badge-success';
  if (status === 'error') return 'badge-danger';
  return 'badge-secondary';
}

export function formatSyncTime(value: string | undefined | null): string {
  if (!value) return 'Never';
  const withTz = value.endsWith('Z') ? value : `${value}Z`;
  const d = new Date(withTz);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}
