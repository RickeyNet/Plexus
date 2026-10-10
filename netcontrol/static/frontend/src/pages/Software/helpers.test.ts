import { describe, expect, it } from 'vitest';

import {
  barWidth,
  formatTime,
  parseAdvisoryImport,
  parseVersionList,
  severityBadgeClass,
  severityLabel,
  severityRank,
  softwareTabFromPath,
  sourceLabel,
} from './helpers';

describe('severity helpers', () => {
  it('maps severities to badge classes', () => {
    expect(severityBadgeClass('critical')).toBe('badge badge-danger');
    expect(severityBadgeClass('High')).toBe('badge badge-danger');
    expect(severityBadgeClass('medium')).toBe('badge badge-warning');
    expect(severityBadgeClass('low')).toBe('badge badge-info');
    expect(severityBadgeClass(undefined)).toBe('badge badge-secondary');
  });

  it('labels and ranks severities', () => {
    expect(severityLabel('critical')).toBe('Critical');
    expect(severityLabel('info')).toBe('Info');
    expect(severityLabel('')).toBe('');
    expect(severityRank('critical')).toBeLessThan(severityRank('high'));
    expect(severityRank('bogus')).toBeGreaterThan(severityRank('info'));
  });
});

describe('sourceLabel', () => {
  it('names the sources and passes unknown ones through', () => {
    expect(sourceLabel('inventory')).toBe('Inventory');
    expect(sourceLabel('cisco-psirt')).toBe('Cisco PSIRT');
    expect(sourceLabel('fmc')).toBe('Cisco FMC');
    expect(sourceLabel('panorama')).toBe('Palo Alto Panorama');
    expect(sourceLabel('custom')).toBe('custom');
    expect(sourceLabel(null)).toBe('');
  });
});

describe('formatTime', () => {
  it('treats the backend UTC text as UTC', () => {
    expect(formatTime('')).toBe('Never');
    const out = formatTime('2026-10-05 21:49:53');
    expect(out).toBe(new Date('2026-10-05T21:49:53Z').toLocaleString());
  });

  it('returns unparseable values unchanged', () => {
    expect(formatTime('soon')).toBe('soon');
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
});

describe('softwareTabFromPath', () => {
  it('opens Upgrades on its path', () => {
    expect(softwareTabFromPath('/software/upgrades')).toBe('upgrades');
  });

  it('opens Versions on any other path', () => {
    expect(softwareTabFromPath('/software')).toBe('versions');
    expect(softwareTabFromPath('/software/other')).toBe('versions');
    expect(softwareTabFromPath('')).toBe('versions');
  });
});

describe('barWidth', () => {
  it('scales to the largest count with a visible minimum', () => {
    expect(barWidth(0, 10)).toBe(0);
    expect(barWidth(10, 10)).toBe(100);
    expect(barWidth(1, 100)).toBe(4);
  });
});
