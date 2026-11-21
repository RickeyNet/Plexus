import type { IpamSubnet } from '@/api/ipam';
import { type CustomDataFilterValue, isEmptyFilter, matchesCustomData } from '@/lib/customData';
import { networksOverlap, parseIpNetwork } from '@/lib/ipNetwork';

export function formatSubnetPreview(item: IpamSubnet): string {
  const parts: string[] = [];
  const hosts = Array.isArray(item.hostnames_preview) ? item.hostnames_preview : [];
  const cloud = Array.isArray(item.cloud_resource_names_preview)
    ? item.cloud_resource_names_preview
    : [];
  const external = Array.isArray(item.external_source_names_preview)
    ? item.external_source_names_preview
    : [];
  const topology = Array.isArray(item.topology_sites_preview)
    ? item.topology_sites_preview
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
  if (topology.length) {
    parts.push(
      `Sites: ${topology.join(', ')}${item.topology_preview_truncated ? ` +${item.topology_preview_truncated}` : ''}`,
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

/** "Meraki", "Cato", "Cisco FMC", "AWS"... for a topology / cloud provider id. */
export function providerLabel(provider: string | undefined): string {
  switch ((provider ?? '').toLowerCase()) {
    case 'meraki':
      return 'Meraki';
    case 'cato':
      return 'Cato';
    case 'fmc':
      return 'Cisco FMC';
    case 'panorama':
      return 'Palo Alto Panorama';
    case 'appgate':
      return 'Appgate SDP';
    case 'opnsense':
      return 'OPNsense';
    case 'aws':
      return 'AWS';
    case 'azure':
      return 'Azure';
    case 'gcp':
      return 'GCP';
    default:
      return provider ?? '';
  }
}

/**
 * Whether an IPAM source or DHCP server is filled by a topology collection
 * (an OPNsense firewall's Map source) rather than synced: it is never synced,
 * validated, reconciled or pushed to from here (the server refuses it too:
 * ``is_collection_fed`` in ``netcontrol/routes/dhcp_adapters.py``).
 */
export function isCollectionFed(provider: string | undefined): boolean {
  return (provider ?? '').trim().toLowerCase() === 'opnsense';
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

export interface ConnectionFieldErrors {
  provider?: string;
  name?: string;
  baseUrl?: string;
}

/**
 * Required-field check shared by the IPAM source and DHCP server forms.
 * Returns one message per missing field; an empty object means valid.
 */
export function validateConnectionForm(values: {
  provider: string;
  name: string;
  baseUrl: string;
}): ConnectionFieldErrors {
  const errors: ConnectionFieldErrors = {};
  if (!values.provider) errors.provider = 'Select a provider.';
  if (!values.name.trim()) errors.name = 'Name is required.';
  if (!values.baseUrl.trim()) errors.baseUrl = 'Base URL is required.';
  return errors;
}

/** The subnets carrying every tag and field value of the filter; an empty filter returns `subnets` unchanged. */
export function filterSubnetsByCustomData(subnets: IpamSubnet[], filter: CustomDataFilterValue): IpamSubnet[] {
  if (isEmptyFilter(filter)) return subnets;
  return subnets.filter((subnet) => matchesCustomData(subnet, filter));
}

/** The text a subnet search matches against: the range, VRF, VLANs, groups, sources, names in the previews and tags. */
function subnetSearchText(item: IpamSubnet): string {
  const parts: Array<string | number | null | undefined> = [
    item.subnet,
    item.vrf_name,
    ...(item.vlan_ids ?? []).map((v) => `vlan ${v}`),
    ...(item.group_names ?? []),
    ...(item.source_types ?? []),
    ...(item.external_source_names_preview ?? []),
    ...(item.hostnames_preview ?? []),
    ...(item.cloud_resource_names_preview ?? []),
    ...(item.topology_sites_preview ?? []),
    ...(item.topology_providers ?? []).map(providerLabel),
    ...(item.tags ?? []).map((t) => t.name),
  ];
  return parts.filter((p) => p != null && p !== '').join('\n').toLowerCase();
}

/**
 * The subnets a search box query picks out. An address ("192.0.2.10") finds
 * the subnets that contain it; a range ("192.0.2.0/23") the subnets inside
 * or around it; anything else is matched as words, each of which must appear
 * in the subnet, VRF, VLANs, groups, sources, previewed names or tags.
 * Hostnames beyond a subnet's preview are not searched.
 */
export function searchSubnets(subnets: IpamSubnet[], query: string): IpamSubnet[] {
  const text = query.trim();
  if (!text) return subnets;
  const wanted = parseIpNetwork(text);
  if (wanted) {
    return subnets.filter((item) => {
      const net = parseIpNetwork(item.subnet);
      return net !== null && networksOverlap(net, wanted);
    });
  }
  const words = text.toLowerCase().split(/\s+/);
  return subnets.filter((item) => {
    const haystack = subnetSearchText(item);
    return words.every((w) => haystack.includes(w));
  });
}
