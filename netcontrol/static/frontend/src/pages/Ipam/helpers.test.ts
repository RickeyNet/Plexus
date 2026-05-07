import { describe, expect, it } from 'vitest';

import {
  driftBadgeClass,
  driftLabel,
  formatSubnetPreview,
  formatSyncTime,
  statusBadgeClass,
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

describe('statusBadgeClass', () => {
  it('returns success/danger/secondary based on status', () => {
    expect(statusBadgeClass('success')).toBe('badge-success');
    expect(statusBadgeClass('error')).toBe('badge-danger');
    expect(statusBadgeClass('never')).toBe('badge-secondary');
    expect(statusBadgeClass(undefined)).toBe('badge-secondary');
  });
});

describe('formatSyncTime', () => {
  it('returns "Never" for null/empty', () => {
    expect(formatSyncTime(null)).toBe('Never');
    expect(formatSyncTime(undefined)).toBe('Never');
    expect(formatSyncTime('')).toBe('Never');
  });

  it('treats input without Z suffix as UTC', () => {
    const out = formatSyncTime('2026-01-02T03:04:05');
    expect(out).not.toBe('2026-01-02T03:04:05');
    expect(out.length).toBeGreaterThan(0);
  });
});
