import { describe, expect, it } from 'vitest';

import {
  complianceStatusRank,
  complianceStatusTone,
  isActiveStatus,
  isCriticalSeverity,
  normalizeSeverity,
  severityRank,
  severityTone,
  statusTone,
  toneColor,
} from './severity';

describe('severityTone', () => {
  it('maps the five levels', () => {
    expect(severityTone('critical')).toBe('danger');
    expect(severityTone('high')).toBe('danger');
    expect(severityTone('medium')).toBe('warning');
    expect(severityTone('low')).toBe('info');
    expect(severityTone('info')).toBe('neutral');
  });

  it('is case-insensitive and trims', () => {
    expect(severityTone('HIGH')).toBe('danger');
    expect(severityTone(' Medium ')).toBe('warning');
  });

  it('folds monitoring and syslog vocabularies onto the levels', () => {
    expect(severityTone('warning')).toBe('warning');
    expect(severityTone('error')).toBe('danger');
    expect(severityTone('emergency')).toBe('danger');
    expect(severityTone('notice')).toBe('info');
    expect(severityTone('informational')).toBe('neutral');
    expect(severityTone('debug')).toBe('neutral');
  });

  it('treats missing, none and unknown as neutral', () => {
    expect(severityTone(null)).toBe('neutral');
    expect(severityTone(undefined)).toBe('neutral');
    expect(severityTone('')).toBe('neutral');
    expect(severityTone('none')).toBe('neutral');
    expect(severityTone('unknown')).toBe('neutral');
    expect(severityTone('something-new')).toBe('neutral');
  });
});

describe('isCriticalSeverity / normalizeSeverity / severityRank', () => {
  it('flags only critical-level severities', () => {
    expect(isCriticalSeverity('critical')).toBe(true);
    expect(isCriticalSeverity('Alert')).toBe(true);
    expect(isCriticalSeverity('high')).toBe(false);
    expect(isCriticalSeverity(null)).toBe(false);
  });

  it('normalizes aliases and returns null for unknown values', () => {
    expect(normalizeSeverity('warn')).toBe('medium');
    expect(normalizeSeverity('err')).toBe('high');
    expect(normalizeSeverity('bogus')).toBeNull();
    expect(normalizeSeverity(undefined)).toBeNull();
  });

  it('ranks most severe first and unknown last', () => {
    const sorted = ['low', 'bogus', 'critical', 'info', 'medium', 'high'].sort(
      (a, b) => severityRank(a) - severityRank(b),
    );
    expect(sorted).toEqual(['critical', 'high', 'medium', 'low', 'info', 'bogus']);
  });
});

describe('complianceStatusTone', () => {
  it('maps pass, fail and scan errors', () => {
    expect(complianceStatusTone('compliant')).toBe('success');
    expect(complianceStatusTone('pass')).toBe('success');
    expect(complianceStatusTone('non-compliant')).toBe('danger');
    expect(complianceStatusTone('non_compliant')).toBe('danger');
    expect(complianceStatusTone('Fail')).toBe('danger');
    expect(complianceStatusTone('violation')).toBe('danger');
    // The scan could not run: not a finding, so not danger.
    expect(complianceStatusTone('error')).toBe('warning');
  });

  it('treats pending, skipped and unknown as neutral', () => {
    expect(complianceStatusTone('pending')).toBe('neutral');
    expect(complianceStatusTone('skipped')).toBe('neutral');
    expect(complianceStatusTone(null)).toBe('neutral');
    expect(complianceStatusTone('')).toBe('neutral');
  });
});

describe('statusTone / isActiveStatus', () => {
  it('maps finished, failed and partial runs', () => {
    expect(statusTone('success')).toBe('success');
    expect(statusTone('completed')).toBe('success');
    expect(statusTone('ok')).toBe('success');
    expect(statusTone('failed')).toBe('danger');
    expect(statusTone('error')).toBe('danger');
    expect(statusTone('verification_failed')).toBe('danger');
    expect(statusTone('partial')).toBe('warning');
    expect(statusTone('rolled-back')).toBe('warning');
  });

  it('maps in-progress statuses to info whatever the separator', () => {
    expect(statusTone('running')).toBe('info');
    expect(statusTone('in_progress')).toBe('info');
    expect(statusTone('In Progress')).toBe('info');
    expect(statusTone('pre-check')).toBe('info');
    expect(isActiveStatus('running')).toBe(true);
    expect(isActiveStatus('completed')).toBe(false);
  });

  it('treats waiting, cancelled and unknown as neutral', () => {
    expect(statusTone('pending')).toBe('neutral');
    expect(statusTone('queued')).toBe('neutral');
    expect(statusTone('cancelled')).toBe('neutral');
    expect(statusTone(undefined)).toBe('neutral');
    expect(statusTone('something-new')).toBe('neutral');
  });
});

describe('toneColor', () => {
  it('returns the theme token for each tone', () => {
    expect(toneColor('danger')).toBe('var(--danger)');
    expect(toneColor('primary')).toBe('var(--primary)');
    expect(toneColor('neutral')).toBe('var(--text-muted)');
  });
});

describe('complianceStatusRank', () => {
  it('orders non-compliant, error, unknown, compliant', () => {
    expect(complianceStatusRank('non-compliant')).toBe(0);
    expect(complianceStatusRank('error')).toBe(1);
    expect(complianceStatusRank('pending')).toBe(2);
    expect(complianceStatusRank(null)).toBe(2);
    expect(complianceStatusRank('compliant')).toBe(3);
  });
});
