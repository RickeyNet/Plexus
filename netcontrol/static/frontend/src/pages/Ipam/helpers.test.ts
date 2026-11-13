import { describe, expect, it } from 'vitest';

import {
  driftBadgeClass,
  driftLabel,
  filterSubnetsByCustomData,
  formatSubnetPreview,
  providerLabel,
  validateConnectionForm,
} from './helpers';

describe('formatSubnetPreview', () => {
  it('returns "No preview" when all preview lists empty', () => {
    expect(formatSubnetPreview({ subnet: '10.0.0.0/24' })).toBe('No preview');
  });

  it('joins host / cloud / external / available previews', () => {
    const out = formatSubnetPreview({
      subnet: '10.0.0.0/24',
      hostnames_preview: ['router1', 'switch1'],
      cloud_resource_names_preview: ['vpc-prod'],
      external_source_names_preview: ['NetBox'],
      available_preview: ['10.0.0.5', '10.0.0.6'],
    });
    expect(out).toContain('Hosts: router1, switch1');
    expect(out).toContain('Cloud: vpc-prod');
    expect(out).toContain('External: NetBox');
    expect(out).toContain('Available: 10.0.0.5, 10.0.0.6');
  });

  it('includes truncation suffixes', () => {
    const out = formatSubnetPreview({
      subnet: '10.0.0.0/24',
      hostnames_preview: ['a'],
      host_preview_truncated: 5,
      cloud_resource_names_preview: ['vpc'],
      cloud_preview_truncated: 3,
    });
    expect(out).toContain('Hosts: a +5');
    expect(out).toContain('Cloud: vpc +3');
  });

  it('lists the topology sites that hold the subnet', () => {
    const out = formatSubnetPreview({
      subnet: '192.168.10.0/24',
      topology_sites_preview: ['Branch-A (VLAN 10 Users)', 'Branch-B (VLAN 10 Users)'],
      topology_preview_truncated: 2,
    });
    expect(out).toBe('Sites: Branch-A (VLAN 10 Users), Branch-B (VLAN 10 Users) +2');
  });
});

describe('providerLabel', () => {
  it('names the topology and cloud providers', () => {
    expect(providerLabel('meraki')).toBe('Meraki');
    expect(providerLabel('fmc')).toBe('Cisco FMC');
    expect(providerLabel('panorama')).toBe('Palo Alto Panorama');
    expect(providerLabel('appgate')).toBe('Appgate SDP');
    expect(providerLabel('aws')).toBe('AWS');
    expect(providerLabel('other')).toBe('other');
    expect(providerLabel(undefined)).toBe('');
  });
});

describe('driftLabel', () => {
  it('maps known drift types', () => {
    expect(driftLabel('missing_in_ipam')).toBe('Missing in IPAM');
    expect(driftLabel('missing_in_plexus')).toBe('Missing in Plexus');
    expect(driftLabel('hostname_mismatch')).toBe('Hostname mismatch');
    expect(driftLabel('status_mismatch')).toBe('Status mismatch');
  });

  it('passes through unknown drift', () => {
    expect(driftLabel('weird')).toBe('weird');
  });
});

describe('driftBadgeClass', () => {
  it('maps drift types to badge classes', () => {
    expect(driftBadgeClass('missing_in_ipam')).toBe('badge-warning');
    expect(driftBadgeClass('missing_in_plexus')).toBe('badge-danger');
    expect(driftBadgeClass('hostname_mismatch')).toBe('badge-warning');
    expect(driftBadgeClass('status_mismatch')).toBe('badge-secondary');
    expect(driftBadgeClass('other')).toBe('badge-secondary');
  });
});

describe('validateConnectionForm', () => {
  it('accepts a complete form', () => {
    expect(
      validateConnectionForm({ provider: 'netbox', name: 'Lab', baseUrl: 'https://ipam.example.com' }),
    ).toEqual({});
  });

  it('flags each missing field', () => {
    expect(validateConnectionForm({ provider: '', name: ' ', baseUrl: '' })).toEqual({
      provider: 'Select a provider.',
      name: 'Name is required.',
      baseUrl: 'Base URL is required.',
    });
  });
});

describe('filterSubnetsByCustomData', () => {
  const core = { id: 1, name: 'core', color: 'blue' };
  const subnets = [
    { subnet: '192.0.2.0/24', tags: [core], custom_fields: { site: 'north' } },
    { subnet: '198.51.100.0/24', custom_fields: { site: 'south' } },
    { subnet: '2001:db8::/32' },
  ];
  const names = (rows: { subnet: string }[]) => rows.map((r) => r.subnet);

  it('filters by tag', () => {
    expect(names(filterSubnetsByCustomData(subnets, { tagIds: [1], fields: {} }))).toEqual(['192.0.2.0/24']);
  });

  it('filters by field value and by has-a-value', () => {
    expect(names(filterSubnetsByCustomData(subnets, { tagIds: [], fields: { site: 'south' } }))).toEqual([
      '198.51.100.0/24',
    ]);
    expect(names(filterSubnetsByCustomData(subnets, { tagIds: [], fields: { site: '*' } }))).toEqual([
      '192.0.2.0/24',
      '198.51.100.0/24',
    ]);
  });

  it('returns the input unchanged for an empty filter', () => {
    expect(filterSubnetsByCustomData(subnets, { tagIds: [], fields: {} })).toBe(subnets);
  });
});
