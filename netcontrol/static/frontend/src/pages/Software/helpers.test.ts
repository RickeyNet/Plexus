import { describe, expect, it } from 'vitest';

import type { SoftwareEolStatus } from '@/api/softwareEol';

import {
  SOFTWARE_EOL_FILTERS,
  barWidth,
  cveRunSummary,
  knownExploitedTitle,
  matchesSoftwareEolFilter,
  parseAdvisoryImport,
  parseVersionList,
  severityLabel,
  severitySourceLabel,
  softwareEolChip,
  softwareEolTone,
  sourceLabel,
  validateSoftwareEolEntry,
} from './helpers';

describe('severity helpers', () => {
  it('labels severities', () => {
    expect(severityLabel('critical')).toBe('Critical');
    expect(severityLabel('info')).toBe('Info');
    expect(severityLabel('')).toBe('');
  });
});

describe('sourceLabel', () => {
  it('names the sources and passes unknown ones through', () => {
    expect(sourceLabel('inventory')).toBe('Inventory');
    expect(sourceLabel('cisco-psirt')).toBe('Cisco PSIRT');
    expect(sourceLabel('fmc')).toBe('Cisco FMC');
    expect(sourceLabel('panorama')).toBe('Palo Alto Panorama');
    expect(sourceLabel('appgate')).toBe('Appgate SDP');
    expect(sourceLabel('opnsense')).toBe('OPNsense');
    expect(sourceLabel('lifecycle')).toBe('End of life');
    expect(sourceLabel('custom')).toBe('custom');
    expect(sourceLabel(null)).toBe('');
  });
});

describe('parseVersionList', () => {
  it('splits on lines and semicolons and drops blanks', () => {
    expect(parseVersionList('17.9.4a\n<17.6.5 ; 15.2(7)E8\n\n')).toEqual(['17.9.4a', '<17.6.5', '15.2(7)E8']);
  });
});

describe('parseAdvisoryImport', () => {
  it('rejects non-JSON and wrong shapes', () => {
    expect(parseAdvisoryImport('nope').error).toBe('Not valid JSON.');
    expect(parseAdvisoryImport('{"x": 1}').error).toContain('Expected a JSON list');
    expect(parseAdvisoryImport('[{"title": "no id"}]').error).toContain('no advisory_id');
    expect(parseAdvisoryImport('[{"advisory_id": "A-1"}]').error).toContain('no affected_versions');
    expect(parseAdvisoryImport('[]').error).toBe('The list is empty.');
  });

  it('accepts a list or an object with advisories, filling defaults', () => {
    const out = parseAdvisoryImport(
      JSON.stringify({
        advisories: [
          {
            id: 'cisco-sa-x',
            affected: '17.3.*, <17.6.5',
            cvss: '9.8',
            severity: 'Critical',
            cves: ['CVE-2026-0001'],
          },
        ],
      }),
    );
    expect(out.error).toBe('');
    expect(out.advisories).toHaveLength(1);
    const adv = out.advisories[0];
    expect(adv.advisory_id).toBe('cisco-sa-x');
    expect(adv.affected_versions).toEqual(['17.3.*', '<17.6.5']);
    expect(adv.cvss).toBe(9.8);
    expect(adv.severity).toBe('critical');
    expect(adv.enabled).toBe(true);
    expect(adv.cves).toEqual(['CVE-2026-0001']);
  });

  it('leaves the severity out when the entry has none', () => {
    const out = parseAdvisoryImport('[{"advisory_id": "A-1", "affected_versions": ["1.0"]}]');
    expect(out.error).toBe('');
    expect('severity' in out.advisories[0]).toBe(false);
  });
});

describe('CVE enrichment helpers', () => {
  it('describes the known-exploited marker', () => {
    expect(knownExploitedTitle(null)).toBe('');
    expect(knownExploitedTitle({ known_exploited: false, kev_date_added: '2024-04-12' })).toBe('');
    expect(
      knownExploitedTitle({
        known_exploited: true,
        kev_date_added: '2024-04-12',
        kev_due_date: '2024-04-19',
        kev_ransomware: 'Unknown',
      }),
    ).toBe('In the CISA Known Exploited Vulnerabilities catalogue, added 2024-04-12, remediation due 2024-04-19.');
    expect(knownExploitedTitle({ known_exploited: true, kev_ransomware: 'Known' })).toBe(
      'In the CISA Known Exploited Vulnerabilities catalogue; known to be used in ransomware campaigns.',
    );
  });

  it('names where a severity comes from', () => {
    expect(severitySourceLabel('admin')).toBe('Severity set by an administrator');
    expect(severitySourceLabel('vendor')).toBe("The vendor's severity rating");
    expect(severitySourceLabel('enriched', 'nvd')).toContain('NVD CVSS score');
    expect(severitySourceLabel(undefined)).toBe('Default severity (not set by a vendor, a CVSS score or an administrator)');
  });

  it('summarises the last run', () => {
    expect(cveRunSummary('', 'x')).toBe('');
    expect(cveRunSummary('completed', '3 CVE(s): 3 looked up at NVD')).toBe('completed: 3 CVE(s): 3 looked up at NVD');
    expect(cveRunSummary('failed', '')).toBe('failed');
  });
});

describe('barWidth', () => {
  it('scales to the largest count with a visible minimum', () => {
    expect(barWidth(0, 10)).toBe(0);
    expect(barWidth(10, 10)).toBe(100);
    expect(barWidth(1, 100)).toBe(4);
  });
});

describe('software end of life', () => {
  const base: SoftwareEolStatus = {
    series: '25.7',
    status: 'end_of_life',
    date: '2026-01-01',
    days: -324,
    source: 'estimate',
    estimate: true,
    basis: 'Estimate',
    successor: '26.1',
    url: '',
    release_date: '',
  };

  it('words the chip by status and marks estimates', () => {
    expect(softwareEolChip(base)).toBe('End of life since 2026-01-01 (estimate)');
    expect(softwareEolChip({ ...base, source: 'entry', estimate: false })).toBe('End of life since 2026-01-01');
    expect(softwareEolChip({ ...base, source: 'reported', estimate: false })).toBe('End of life (26.1 available)');
    expect(softwareEolChip({ ...base, source: 'reported', successor: '' })).toBe('End of life (newer series available)');
    expect(softwareEolChip({ ...base, status: 'ending', days: 23, estimate: false })).toBe('Ends in 23 days');
    expect(softwareEolChip({ ...base, status: 'ending', days: 1 })).toBe('Ends in 1 day (estimate)');
    expect(softwareEolChip({ ...base, status: 'supported', date: '2027-07-01' })).toBe(
      'Supported until 2027-07-01 (estimate)',
    );
    expect(softwareEolChip({ ...base, status: 'unknown' })).toBe('');
    expect(softwareEolChip(null)).toBe('');
  });

  it('tones the chip and filters by status', () => {
    expect(softwareEolTone(base)).toBe('danger');
    expect(softwareEolTone({ ...base, status: 'ending' })).toBe('warning');
    expect(softwareEolTone({ ...base, status: 'supported' })).toBe('success');
    expect(softwareEolTone(undefined)).toBe('neutral');
    expect(matchesSoftwareEolFilter(base, '')).toBe(true);
    expect(matchesSoftwareEolFilter(base, 'end_of_life')).toBe(true);
    expect(matchesSoftwareEolFilter(base, 'ending')).toBe(false);
    expect(matchesSoftwareEolFilter(null, 'unknown')).toBe(true);
    expect(SOFTWARE_EOL_FILTERS.map((f) => f.value)).toEqual(['end_of_life', 'ending', 'supported', 'unknown']);
  });

  it('validates an entry as the server does', () => {
    const ok = { platform: 'ios-xe', series: '17.9', eol_date: '2027-01-31' };
    expect(validateSoftwareEolEntry(ok)).toEqual({});
    expect(validateSoftwareEolEntry({ ...ok, series: '15.2(7)' })).toEqual({});
    expect(Object.keys(validateSoftwareEolEntry({ platform: '', series: '', eol_date: '' }))).toEqual([
      'platform',
      'series',
      'eol_date',
    ]);
    expect(validateSoftwareEolEntry({ ...ok, series: '17.9 x' }).series).toBeTruthy();
    expect(validateSoftwareEolEntry({ ...ok, eol_date: '2027-02-30' }).eol_date).toBeTruthy();
    expect(validateSoftwareEolEntry({ ...ok, release_date: '2027-06-01' }).release_date).toBeTruthy();
    expect(validateSoftwareEolEntry({ ...ok, url: 'ftp://example.com' }).url).toBeTruthy();
  });
});
