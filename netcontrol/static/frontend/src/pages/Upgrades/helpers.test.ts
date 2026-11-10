import { describe, expect, it } from 'vitest';

import {
  bootModeDisplay,
  campaignStatusBadgeClass,
  campaignStatusLabel,
  formatBytes,
  formatEta,
  formatScheduledTime,
  phaseLabel,
} from './helpers';

describe('bootModeDisplay', () => {
  it('labels install, bundle and unread modes', () => {
    expect(bootModeDisplay('install')).toMatchObject({ label: 'INSTALL', badgeClass: 'badge-success' });
    expect(bootModeDisplay('bundle')).toMatchObject({ label: 'BUNDLE', badgeClass: 'badge-danger' });
    expect(bootModeDisplay('')).toMatchObject({ label: '-', badgeClass: '' });
    expect(bootModeDisplay(undefined).label).toBe('-');
  });
});

describe('formatEta', () => {
  it('renders scp-style clocks', () => {
    expect(formatEta(0)).toBe('00:00');
    expect(formatEta(54)).toBe('00:54');
    expect(formatEta(727.9)).toBe('12:07');
    expect(formatEta(3753)).toBe('1:02:33');
  });

  it('shows --:-- when unknown', () => {
    expect(formatEta(null)).toBe('--:--');
    expect(formatEta(undefined)).toBe('--:--');
    expect(formatEta(-1)).toBe('--:--');
    expect(formatEta(Infinity)).toBe('--:--');
  });
});

describe('formatBytes', () => {
  it('handles each scale', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(2048)).toBe('2.0 KB');
    expect(formatBytes(5 * 1024 * 1024)).toBe('5.0 MB');
    expect(formatBytes(2 * 1024 * 1024 * 1024)).toBe('2.00 GB');
  });
});

describe('phaseLabel', () => {
  it('maps known phases', () => {
    expect(phaseLabel('prestage')).toBe('Prestage');
    expect(phaseLabel('verify_prestage')).toBe('Check Status');
  });

  it('falls back to title-cased input for unknown phases', () => {
    expect(phaseLabel('do_something_else')).toBe('Do Something Else');
  });
});

describe('campaignStatusBadgeClass', () => {
  it('prefers failed over running', () => {
    expect(campaignStatusBadgeClass('prestage_failed', true)).toBe('badge-danger');
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
