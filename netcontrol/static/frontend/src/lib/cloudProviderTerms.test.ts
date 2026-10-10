import { describe, expect, it } from 'vitest';

import { providerForm } from '@/pages/CloudVisibility/accountForm';
import { ANY_CLOUD_TERMS, cloudProviderTerms, cloudTerms } from './cloudProviderTerms';

describe('cloudProviderTerms', () => {
  it('names each provider in its own words', () => {
    const aws = cloudProviderTerms('aws');
    expect(aws.scopeTitle).toBe('AWS account');
    expect(aws.identifierLabel).toBe('AWS account ID');
    expect(aws.network).toBe('VPC');
    expect(aws.flowLogs).toBe('VPC Flow Logs');
    expect(aws.onTopologyMap).toBe(true);

    const azure = cloudProviderTerms('Azure');
    expect(azure.scopeTitle).toBe('Azure subscription');
    expect(azure.identifierLabel).toBe('Subscription ID');
    expect(azure.network).toBe('VNet');
    expect(azure.flowLogs).toBe('NSG flow logs');
    expect(azure.onTopologyMap).toBe(true);

    const gcp = cloudProviderTerms('gcp');
    expect(gcp.scopeTitle).toBe('GCP project');
    expect(gcp.identifierLabel).toBe('Project ID');
    expect(gcp.network).toBe('VPC network');
    expect(gcp.flowLogs).toBe('VPC Flow Logs');
    expect(gcp.onTopologyMap).toBe(true);
  });

  it('labels the identifier as the account form does', () => {
    for (const id of ['aws', 'azure', 'gcp']) {
      expect(cloudProviderTerms(id).identifierLabel).toBe(providerForm(id).identifierLabel);
    }
  });

  it('falls back to generic terms for an unknown provider', () => {
    const oci = cloudProviderTerms('oci');
    expect(oci.label).toBe('oci');
    expect(oci.scope).toBe('account');
    expect(oci.network).toBe('network');
    expect(oci.onTopologyMap).toBe(false);
  });
});

describe('cloudTerms', () => {
  it('uses the mixed terms when no provider is selected', () => {
    expect(cloudTerms('')).toBe(ANY_CLOUD_TERMS);
    expect(cloudTerms(null)).toBe(ANY_CLOUD_TERMS);
    expect(cloudTerms('all')).toBe(ANY_CLOUD_TERMS);
    expect(cloudTerms('azure').scopeTitle).toBe('Azure subscription');
  });
});
