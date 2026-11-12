import type { CloudAccountProvider, CloudProvider } from '@/api/meraki';
import type { AddSourceAccess } from '@/lib/addSource';
import { cloudProviderTerms } from '@/lib/cloudProviderTerms';

import { SOURCE_FORM_CONFIGS } from './sourceFormConfigs';

/** Where cloud accounts are added; `?add=<provider>` opens its Add dialog. */
export const CLOUD_ACCOUNTS_PATH = '/cloud-visibility';

/**
 * One kind of source that can be added. An `org` source opens its form
 * (SourceFormModal); a `cloud` account is added under Cloud Visibility, so
 * it is a link (`to`).
 */
export type AddSourceOption =
  | { kind: 'org'; provider: CloudProvider; label: string; description: string }
  | { kind: 'cloud'; provider: CloudAccountProvider; label: string; description: string; to: string };

const ORG_DESCRIPTIONS: Record<CloudProvider, string> = {
  meraki: 'A Cisco Meraki organization: its networks, devices, uplinks and VPN',
  cato: 'A Cato Networks account: its sites, Sockets, tunnels and remote users',
  fmc: 'A Cisco Secure Firewall Management Center and the FTDs it manages',
  panorama: 'A Palo Alto Networks Panorama and the firewalls it manages',
  appgate: 'An Appgate SDP collective: its Controllers, Gateways, sites, entitlements and connected users',
};

const CLOUD_DESCRIPTIONS: Record<CloudAccountProvider, string> = {
  aws: 'VPCs, subnets, gateways and instances; also used for flow logs and policy',
  azure: 'Virtual networks, gateways and virtual machines; also used for flow logs and policy',
  gcp: 'VPC networks, subnets and instances; also used for flow logs and policy',
};

const ORG_ORDER: readonly CloudProvider[] = ['meraki', 'cato', 'fmc', 'panorama', 'appgate'];
const CLOUD_ORDER: readonly CloudAccountProvider[] = ['aws', 'azure', 'gcp'];

/** "AWS account" -> "AWS Account": the option labels are in title case. */
function titleCase(text: string): string {
  return text.replace(/\b[a-z]/g, (c) => c.toUpperCase());
}

/** The sources this user may add, organization sources first. */
export function addSourceOptions(access: AddSourceAccess): AddSourceOption[] {
  const options: AddSourceOption[] = [];
  if (access.org) {
    for (const provider of ORG_ORDER) {
      options.push({
        kind: 'org',
        provider,
        label: SOURCE_FORM_CONFIGS[provider].noun,
        description: ORG_DESCRIPTIONS[provider],
      });
    }
  }
  if (access.cloud) {
    for (const provider of CLOUD_ORDER) {
      options.push({
        kind: 'cloud',
        provider,
        label: titleCase(cloudProviderTerms(provider).scopeTitle),
        description: CLOUD_DESCRIPTIONS[provider],
        to: `${CLOUD_ACCOUNTS_PATH}?add=${provider}`,
      });
    }
  }
  return options;
}
