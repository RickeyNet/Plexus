import { describe, expect, it } from 'vitest';

import { advisoryId, evaluate, findings, inRange } from './audit-gate.mjs';

const PICO = {
  name: 'picomatch',
  title: 'ReDoS',
  url: 'https://github.com/advisories/GHSA-fc5q-39xc-vjpf',
  severity: 'high',
  range: '<=4.0.7',
};
const MINI = {
  name: 'minimatch',
  title: 'DoS',
  url: 'https://github.com/advisories/GHSA-g3hv-75wg-m249',
  severity: 'moderate',
  range: '>=7.0.0 <11.0.1',
};
const REPORT = {
  vulnerabilities: {
    picomatch: { via: [PICO] },
    vite: { via: ['picomatch'] },
    minimatch: { via: [MINI] },
  },
};
const ENTRY = { id: 'GHSA-fc5q-39xc-vjpf', package: 'picomatch', reason: 'no fix', recheck_by: '2027-01-31' };
const TODAY = '2026-11-17';

describe('findings', () => {
  it('keeps advisories at or above the level, once each', () => {
    const doubled = { vulnerabilities: { ...REPORT.vulnerabilities, other: { via: [PICO] } } };
    expect(findings(doubled, 'high').map((f) => [f.id, f.package])).toEqual([['GHSA-fc5q-39xc-vjpf', 'picomatch']]);
    expect(findings(REPORT, 'moderate').map((f) => f.package)).toEqual(['picomatch', 'minimatch']);
    expect(() => findings(REPORT, 'severe')).toThrow('unknown audit level');
  });

  it('reads the advisory ID from its URL', () => {
    expect(advisoryId(PICO.url)).toBe('GHSA-fc5q-39xc-vjpf');
    expect(advisoryId('https://example.com/x')).toBeNull();
  });
});

describe('inRange', () => {
  it('reads npm advisory ranges', () => {
    expect(inRange('4.0.7', '<=4.0.7')).toBe(true);
    expect(inRange('4.0.8', '<=4.0.7')).toBe(false);
    expect(inRange('10.2.6', '>=7.0.0 <11.0.1')).toBe(true);
    expect(inRange('11.0.9', '>=7.0.0 <11.0.1')).toBe(false);
    expect(inRange('1.5.0', '<1.2.3 || >=1.4.0 <1.6.0')).toBe(true);
    expect(inRange('2.0.0', '*')).toBe(true);
    expect(inRange('4.0.7', 'latest-ish')).toBeNull();
  });
});

describe('evaluate', () => {
  const found = findings(REPORT, 'high');
  const stillVulnerable = () => '4.0.7';

  it('excuses an allowlisted advisory with no fix published', () => {
    const v = evaluate(found, [ENTRY], { today: TODAY, latest: stillVulnerable });
    expect(v.failures).toEqual([]);
    expect(v.excused).toHaveLength(1);
  });

  it('fails an advisory not on the list', () => {
    expect(evaluate(found, [], { today: TODAY, latest: stillVulnerable }).failures[0]).toMatch(/not allowlisted/);
  });

  it('fails once the recheck date has passed', () => {
    const v = evaluate(found, [ENTRY], { today: '2027-02-01', latest: stillVulnerable });
    expect(v.failures[0]).toMatch(/expired on 2027-01-31/);
  });

  it('fails once a fixed version is published, or when it cannot tell', () => {
    expect(evaluate(found, [ENTRY], { today: TODAY, latest: () => '4.0.8' }).failures[0]).toMatch(/upgrade/);
    expect(evaluate(found, [ENTRY], { today: TODAY, latest: () => null }).failures[0]).toMatch(/cannot tell/);
  });

  it('fails a stale or incomplete entry', () => {
    const stale = evaluate([], [ENTRY], { today: TODAY, latest: stillVulnerable });
    expect(stale.failures[0]).toMatch(/matches no reported advisory/);
    const bad = evaluate(found, [{ ...ENTRY, reason: '' }], { today: TODAY, latest: stillVulnerable });
    expect(bad.failures[0]).toMatch(/needs id, package, reason and recheck_by/);
  });
});
