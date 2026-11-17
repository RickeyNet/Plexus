import { CLOUD_ACCOUNT_PROVIDERS, ORG_PROVIDERS } from '@/api/meraki';
import type { SlaTarget } from '@/api/monitoring';
import { providerLabel } from '@/pages/Topology/helpers';

// What an SLA target covers: inventory hosts (every host, a group, one host)
// or the entities an integration's collections track (gateway uplinks,
// tunnels, sites...), which the server evaluates in the same pass.

export type TargetScope = 'global' | 'group' | 'host' | 'integration';

/** Every integration whose entities the topology availability tracker follows. */
export const INTEGRATION_PROVIDERS: readonly string[] = [...ORG_PROVIDERS, ...CLOUD_ACCOUNT_PROVIDERS];

/** The tracked entity types, in the order the form lists them. */
export const ENTITY_TYPE_LABELS: Record<string, string> = {
  device: 'Devices',
  site: 'Sites',
  uplink: 'Uplinks (gateways)',
  tunnel: 'Tunnels',
  vpn_connection: 'VPN connections',
  circuit: 'Circuits',
  peering: 'Peerings',
  link: 'Links',
  service: 'Cloud services',
};

/** What an SLA target covers, for the list of targets. */
export function slaTargetScopeLabel(t: SlaTarget): string {
  if (t.provider) {
    const kind = t.entity_type ? (ENTITY_TYPE_LABELS[t.entity_type] ?? t.entity_type).toLowerCase() : 'all entities';
    return `Integration: ${providerLabel(t.provider)}, ${kind}`;
  }
  if (t.host_name) return `Host: ${t.host_name}`;
  return t.group_name ? `Group: ${t.group_name}` : 'Global';
}
