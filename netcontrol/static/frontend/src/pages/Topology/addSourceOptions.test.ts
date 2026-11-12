import { describe, expect, it } from 'vitest';

import { addSourceOptions } from './addSourceOptions';

describe('addSourceOptions', () => {
  it('lists organization sources first, then cloud accounts', () => {
    const options = addSourceOptions({ org: true, cloud: true });
    expect(options.map((o) => o.label)).toEqual([
      'Meraki Organization',
      'Cato Account',
      'Cisco FMC',
      'Palo Alto Panorama',
      'Appgate SDP',
      'AWS Account',
      'Azure Subscription',
      'GCP Project',
    ]);
    expect(options.every((o) => o.description.length > 0)).toBe(true);
  });

  it('links each cloud account to its Add dialog under Cloud Visibility', () => {
    const cloud = addSourceOptions({ org: false, cloud: true });
    expect(cloud.map((o) => (o.kind === 'cloud' ? o.to : null))).toEqual([
      '/cloud-visibility?add=aws',
      '/cloud-visibility?add=azure',
      '/cloud-visibility?add=gcp',
    ]);
  });

  it('leaves out what the user may not add', () => {
    expect(addSourceOptions({ org: true, cloud: false }).every((o) => o.kind === 'org')).toBe(true);
    expect(addSourceOptions({ org: false, cloud: false })).toEqual([]);
  });
});
