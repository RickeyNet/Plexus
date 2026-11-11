import { describe, expect, it } from 'vitest';

import type { RunScanBulkResult } from '@/api/compliance';

import { findingOutcome, hostScanOutcome, scanPercent } from './scanHelpers';

const result = (partial: Partial<RunScanBulkResult>): RunScanBulkResult => ({
  hosts_scanned: 0,
  violations: 0,
  errors: 0,
  results: [],
  ...partial,
});

describe('scanPercent', () => {
  it('is null until the total is known', () => {
    expect(scanPercent(0, 0)).toBeNull();
    expect(scanPercent(undefined, null)).toBeNull();
  });

  it('rounds the share of hosts done', () => {
    expect(scanPercent(1, 3)).toBe(33);
    expect(scanPercent(4, 4)).toBe(100);
  });
});

describe('hostScanOutcome', () => {
  it('reports a failed job with its error', () => {
    expect(hostScanOutcome({ status: 'failed', result: null, error: 'credential not found' })).toEqual({
      tone: 'danger',
      message: 'Scan failed: credential not found',
    });
  });

  it('counts non-compliant hosts and errors', () => {
    const out = hostScanOutcome({
      status: 'completed',
      result: result({ hosts_scanned: 5, violations: 2, errors: 1 }),
      error: null,
    });
    expect(out.tone).toBe('warning');
    expect(out.message).toBe('5 host(s) scanned, 2 non-compliant, 1 error(s).');
  });

  it('reports errors without violations as danger', () => {
    const out = hostScanOutcome({ status: 'completed', result: result({ hosts_scanned: 3, errors: 3 }), error: null });
    expect(out).toEqual({ tone: 'danger', message: '3 host(s) scanned, 3 error(s).' });
  });

  it('reports an all-compliant scan', () => {
    const out = hostScanOutcome({ status: 'completed', result: result({ hosts_scanned: 4 }), error: null });
    expect(out).toEqual({ tone: 'success', message: '4 host(s) scanned - all compliant.' });
  });

  it('warns on an empty or partial scan', () => {
    expect(hostScanOutcome({ status: 'completed', result: result({}), error: null }).tone).toBe('warning');
    const partial = hostScanOutcome({
      status: 'partial',
      result: result({ hosts_scanned: 2 }),
      error: 'Stopped after 2 of 3 hosts.',
    });
    expect(partial.tone).toBe('warning');
    expect(partial.message).toBe('2 host(s) scanned - all compliant. Stopped after 2 of 3 hosts.');
  });
});

describe('findingOutcome', () => {
  it('maps pass, fail and unreadable', () => {
    expect(findingOutcome({ passed: true })).toEqual({ label: 'PASS', tone: 'success' });
    expect(findingOutcome({ passed: false })).toEqual({ label: 'FAIL', tone: 'danger' });
    expect(findingOutcome({ passed: null, unreadable: true })).toEqual({ label: 'UNREADABLE', tone: 'warning' });
  });
});
