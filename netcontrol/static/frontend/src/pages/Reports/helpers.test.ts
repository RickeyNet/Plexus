import { describe, expect, it } from 'vitest';

import { artifactTypeLabel, columnLabel, reportTypeLabel } from './helpers';

describe('columnLabel', () => {
  it('turns a row key into a sentence-case header', () => {
    expect(columnLabel('hostname')).toBe('Hostname');
    expect(columnLabel('uptime_seconds')).toBe('Uptime seconds');
    expect(columnLabel('last_seen')).toBe('Last seen');
  });

  it('keeps the spelling of acronyms and units', () => {
    expect(columnLabel('ip_address')).toBe('IP address');
    expect(columnLabel('host_id')).toBe('Host ID');
    expect(columnLabel('avg_cpu_pct')).toBe('Avg CPU %');
    expect(columnLabel('in_bps')).toBe('In bps');
  });

  it('leaves an empty key alone', () => {
    expect(columnLabel('')).toBe('');
  });
});

describe('reportTypeLabel', () => {
  it('uses the names the Generate form shows', () => {
    expect(reportTypeLabel('interface')).toBe('Interface Utilization');
    expect(reportTypeLabel('network_documentation')).toBe('Network Documentation');
  });

  it('reads an unknown type as words and a missing one as "-"', () => {
    expect(reportTypeLabel('custom_export')).toBe('Custom export');
    expect(reportTypeLabel(undefined)).toBe('-');
  });
});

describe('artifactTypeLabel', () => {
  it('names known artifact types', () => {
    expect(artifactTypeLabel('svg')).toBe('SVG');
    expect(artifactTypeLabel('drawio')).toBe('draw.io');
  });

  it('upper-cases unknown types and names a missing one', () => {
    expect(artifactTypeLabel('xlsx')).toBe('XLSX');
    expect(artifactTypeLabel(undefined)).toBe('File');
  });
});
