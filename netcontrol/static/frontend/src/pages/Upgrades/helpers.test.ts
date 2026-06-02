import { describe, expect, it } from 'vitest';

import {
  campaignStatusBadgeClass,
  campaignStatusLabel,
  formatBackupTimestamp,
  formatBytes,
  formatRelativeTime,
  formatScheduledTime,
  phaseLabel,
} from './helpers';

describe('formatBytes', () => {
  it('handles each scale', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(2048)).toBe('2.0 KB');
    expect(formatBytes(5 * 1024 * 1024)).toBe('5.0 MB');
    expect(formatBytes(2 * 1024 * 1024 * 1024)).toBe('2.00 GB');
  });
});

describe('formatBackupTimestamp', () => {
  it('strips T and trims sub-second precision', () => {
    expect(formatBackupTimestamp('2026-05-07T15:31:42.123456')).toBe('2026-05-07 15:31:42');
  });

  it('returns empty for null/undefined', () => {
    expect(formatBackupTimestamp(null)).toBe('');
    expect(formatBackupTimestamp(undefined)).toBe('');
    expect(formatBackupTimestamp('')).toBe('');
  });
});

describe('phaseLabel', () => {
  it('maps known phases', () => {
    expect(phaseLabel('prestage')).toBe('Prestage');
    expect(phaseLabel('verify_prestage')).toBe('Re-Verify Prestage');
  });

  it('falls back to title-cased input for unknown phases', () => {
    expect(phaseLabel('do_something_else')).toBe('Do Something Else');
  });
});

describe('campaignStatusBadgeClass', () => {
  it('prefers failed over running', () => {
    expect(campaignStatusBadgeClass('prestage_failed', true)).toBe('badge-error');
  });
  it('returns info for running campaigns', () => {
    expect(campaignStatusBadgeClass('running_prestage', true)).toBe('badge-info');
  });
  it('returns success for complete', () => {
    expect(campaignStatusBadgeClass('prestage_complete', false)).toBe(
      'badge-success',
    );
  });
  it('falls back to secondary', () => {
    expect(campaignStatusBadgeClass('created', false)).toBe('badge-secondary');
    expect(campaignStatusBadgeClass(null, false)).toBe('badge-secondary');
  });
  it('marks scheduled and missed as warning even when armed', () => {
    // A scheduled campaign keeps an armed task, so isRunning is true.
    expect(campaignStatusBadgeClass('scheduled_activate', true)).toBe(
      'badge-warning',
    );
    expect(campaignStatusBadgeClass('activate_missed', false)).toBe(
      'badge-warning',
    );
  });
});

describe('campaignStatusLabel', () => {
  it('maps known statuses to friendly text', () => {
    expect(campaignStatusLabel('scheduled_activate')).toBe('Reload scheduled');
    expect(campaignStatusLabel('running_activate')).toBe('Activating (reload)…');
    expect(campaignStatusLabel('activate_missed')).toBe(
      'Reload missed — reschedule',
    );
  });
  it('falls back generically for unknown phase statuses', () => {
    expect(campaignStatusLabel('transfer_failed')).toBe('Transfer failed');
    expect(campaignStatusLabel(null)).toBe('Created');
  });
});

describe('formatRelativeTime', () => {
  const now = Date.UTC(2026, 5, 1, 12, 0, 0);
  it('formats future spans with two units', () => {
    expect(formatRelativeTime(now + (2 * 3600 + 15 * 60) * 1000, now)).toBe(
      'in 2h 15m',
    );
    expect(formatRelativeTime(now + 45 * 60 * 1000, now)).toBe('in 45m');
  });
  it('formats past spans and the near-now window', () => {
    expect(formatRelativeTime(now - 26 * 3600 * 1000, now)).toBe('1d 2h ago');
    expect(formatRelativeTime(now + 30 * 1000, now)).toBe('in <1m');
  });
});

describe('formatScheduledTime', () => {
  it('returns null for missing or unparseable input', () => {
    expect(formatScheduledTime(null)).toBeNull();
    expect(formatScheduledTime('not-a-date')).toBeNull();
  });
  it('derives a relative span from the parsed instant', () => {
    const iso = '2026-06-01T12:30:00+00:00';
    const now = Date.UTC(2026, 5, 1, 12, 0, 0);
    expect(formatScheduledTime(iso, now)?.relative).toBe('in 30m');
  });
});
