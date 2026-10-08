// The words the Cloud Visibility pages use for each provider, so that an
// Azure subscription is never called an account or a VNet a VPC.

export interface CloudProviderTerms {
  id: string;
  label: string;
  fullName: string;
  /** The thing one entry is: 'account', 'subscription' or 'project'. */
  scope: string;
  scopePlural: string;
  /** With the provider: 'AWS account', 'Azure subscription', 'GCP project'. */
  scopeTitle: string;
  scopeTitlePlural: string;
  /** Same as the account form's identifierLabel. */
  identifierLabel: string;
  network: string;
  networks: string;
  /** What the Regions cell says when nothing restricts discovery. */
  wholeScope: string;
  flowLogs: string;
  flowSource: string;
  metricsSource: string;
  policy: string;
  policyShort: string;
  compute: string;
  api: string;
  /** Drawn on the Topology map by netcontrol/integrations/{aws,azure}. */
  onTopologyMap: boolean;
}

const AWS: CloudProviderTerms = {
  id: 'aws',
  label: 'AWS',
  fullName: 'Amazon Web Services',
  scope: 'account',
  scopePlural: 'accounts',
  scopeTitle: 'AWS account',
  scopeTitlePlural: 'AWS accounts',
  identifierLabel: 'AWS account ID',
  network: 'VPC',
  networks: 'VPCs',
  wholeScope: 'All regions',
  flowLogs: 'VPC Flow Logs',
  flowSource: 'CloudWatch Logs',
  metricsSource: 'CloudWatch',
  policy: 'security groups and network ACLs',
  policyShort: 'Security groups',
  compute: 'EC2 instance',
  api: 'the AWS APIs',
  onTopologyMap: true,
};

const AZURE: CloudProviderTerms = {
  id: 'azure',
  label: 'Azure',
  fullName: 'Microsoft Azure',
  scope: 'subscription',
  scopePlural: 'subscriptions',
  scopeTitle: 'Azure subscription',
  scopeTitlePlural: 'Azure subscriptions',
  identifierLabel: 'Subscription ID',
  network: 'VNet',
  networks: 'VNets',
  wholeScope: 'Whole subscription',
  flowLogs: 'NSG flow logs',
  flowSource: 'a storage account',
  metricsSource: 'Azure Monitor',
  policy: 'network security groups',
  policyShort: 'NSGs',
  compute: 'virtual machine',
  api: 'Azure Resource Manager',
  onTopologyMap: true,
};

const GCP: CloudProviderTerms = {
  id: 'gcp',
  label: 'GCP',
  fullName: 'Google Cloud Platform',
  scope: 'project',
  scopePlural: 'projects',
  scopeTitle: 'GCP project',
  scopeTitlePlural: 'GCP projects',
  identifierLabel: 'Project ID',
  network: 'VPC network',
  networks: 'VPC networks',
  wholeScope: 'Whole project',
  flowLogs: 'VPC Flow Logs',
  flowSource: 'Cloud Logging',
  metricsSource: 'Cloud Monitoring',
  policy: 'firewall rules',
  policyShort: 'Firewall rules',
  compute: 'Compute Engine instance',
  api: 'the Google Cloud APIs',
  onTopologyMap: false,
};

/** For a view that mixes providers ("All Providers"). */
export const ANY_CLOUD_TERMS: CloudProviderTerms = {
  id: '',
  label: 'Cloud',
  fullName: 'Cloud',
  scope: 'account',
  scopePlural: 'accounts',
  scopeTitle: 'cloud account',
  scopeTitlePlural: 'cloud accounts',
  identifierLabel: 'Account / subscription / project ID',
  network: 'cloud network',
  networks: 'VPCs and VNets',
  wholeScope: 'All regions',
  flowLogs: 'flow logs',
  flowSource: 'the provider',
  metricsSource: 'the provider',
  policy: 'security groups, NSGs and firewall rules',
  policyShort: 'Security rules',
  compute: 'instance',
  api: 'the provider APIs',
  onTopologyMap: false,
};

function genericTerms(id: string): CloudProviderTerms {
  return {
    id,
    label: id,
    fullName: id,
    scope: 'account',
    scopePlural: 'accounts',
    scopeTitle: `${id} account`,
    scopeTitlePlural: `${id} accounts`,
    identifierLabel: 'Account / Subscription / Project',
    network: 'network',
    networks: 'networks',
    wholeScope: 'Whole account',
    flowLogs: 'flow logs',
    flowSource: 'the provider',
    metricsSource: 'the provider',
    policy: 'network policies',
    policyShort: 'Network policies',
    compute: 'instance',
    api: `the ${id} APIs`,
    onTopologyMap: false,
  };
}

const BY_ID: Record<string, CloudProviderTerms> = { aws: AWS, azure: AZURE, gcp: GCP };

export function cloudProviderTerms(provider?: string | null): CloudProviderTerms {
  const raw = String(provider ?? '').trim();
  return BY_ID[raw.toLowerCase()] ?? genericTerms(raw);
}

/** ANY_CLOUD_TERMS when no single provider is selected. */
export function cloudTerms(provider?: string | null): CloudProviderTerms {
  const id = String(provider ?? '').trim().toLowerCase();
  return !id || id === 'all' ? ANY_CLOUD_TERMS : cloudProviderTerms(id);
}

export function capitalize(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}
