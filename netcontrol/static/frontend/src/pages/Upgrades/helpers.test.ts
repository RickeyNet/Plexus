import { describe, expect, it } from 'vitest';

import { formatBackupTimestamp, formatBytes } from './helpers';

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
