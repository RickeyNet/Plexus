import { describe, expect, it } from 'vitest';

import type { ConfigDriftEvent } from '@/api/configuration';

import {
  backupDiffAvailable,
  filterDriftEvents,
  groupDriftEvents,
  NO_CREDENTIAL,
  policyCredentialChoice,
  policyCredentialId,
  policyCredentialNote,
  runBackupPolicyMessage,
  statusColor,
} from './helpers';

const ev = (
  id: number,
  partial: Partial<ConfigDriftEvent>,
): ConfigDriftEvent => ({
  id,
  host_id: id,
  status: 'open',
  ...partial,
});

describe('statusColor', () => {
  it('maps known statuses', () => {
    expect(statusColor('open')).toBe('var(--danger)');
    expect(statusColor('accepted')).toBe('var(--warning)');
    expect(statusColor('resolved')).toBe('var(--success)');
  });

  it('defaults to success for unknown', () => {
    expect(statusColor(null)).toBe('var(--success)');
  });
});

describe('groupDriftEvents', () => {
  it('groups events by the change key the server sends', () => {
    const a = ev(1, { diff_key: 'aaaa' });
    const b = ev(2, { diff_key: 'aaaa' });
    const c = ev(3, { diff_key: 'bbbb' });
    const groups = groupDriftEvents([c, a, b]);
    expect(groups).toHaveLength(2);
    expect(groups[0].events.map((e) => e.id)).toEqual([1, 2]);
    expect(groups[1].events.map((e) => e.id)).toEqual([3]);
    // The first event of a group is the one whose diff the card shows.
    expect(groups[0].representative_id).toBe(1);
  });

  it('puts events without a key in one group', () => {
    expect(groupDriftEvents([ev(1, {}), ev(2, { diff_key: '' })])).toHaveLength(1);
  });
});

describe('filterDriftEvents', () => {
  const events = [
    ev(1, { hostname: 'core-sw1', ip_address: '10.0.0.1' }),
    ev(2, { hostname: 'edge-rtr', ip_address: '10.0.0.2', device_type: 'cisco_ios' }),
  ];

  it('returns all events when query is empty', () => {
    expect(filterDriftEvents(events, '')).toHaveLength(2);
  });

  it('filters by hostname', () => {
    expect(filterDriftEvents(events, 'core')).toHaveLength(1);
  });

  it('filters by device type', () => {
    expect(filterDriftEvents(events, 'cisco')).toHaveLength(1);
  });

  it('is case-insensitive', () => {
    expect(filterDriftEvents(events, 'CORE-SW1')).toHaveLength(1);
  });
});

describe('backupDiffAvailable', () => {
  it('allows diffing successful backups', () => {
    expect(backupDiffAvailable('success')).toBe(true);
  });

  it('blocks diffing failed backups', () => {
    expect(backupDiffAvailable('failed')).toBe(false);
  });

  it('allows the diff view while status is unknown', () => {
    expect(backupDiffAvailable(undefined)).toBe(true);
    expect(backupDiffAvailable(null)).toBe(true);
  });
});

describe('backup policy credential', () => {
  it('starts a new policy with nothing chosen', () => {
    expect(policyCredentialChoice(null)).toBeNull();
  });

  it('starts a saved policy with its credential, or None when it has none', () => {
    expect(policyCredentialChoice({ credential_id: 4 })).toBe(4);
    expect(policyCredentialChoice({ credential_id: null })).toBe(NO_CREDENTIAL);
  });

  it('saves None as a null credential_id', () => {
    expect(policyCredentialId(NO_CREDENTIAL)).toBeNull();
    expect(policyCredentialId(7)).toBe(7);
  });

  it('notes a policy without a credential in the list', () => {
    expect(policyCredentialNote({ credential_id: null })).toMatch(/API-read devices/);
    expect(policyCredentialNote({ credential_id: 3 })).toBeNull();
  });
});

describe('runBackupPolicyMessage', () => {
  const failure = (n: number) => ({
    host_id: n,
    hostname: `fw${n}`,
    ip_address: `192.0.2.${n}`,
    error: `reason ${n}`,
  });

  it('gives the counts of a run without errors', () => {
    expect(runBackupPolicyMessage({ backed_up: 12, errors: 0, skipped: 3, failures: [] })).toBe(
      'Backup complete: 12 saved, 0 errors, 3 unchanged (skipped)',
    );
    expect(runBackupPolicyMessage({ backed_up: 1, errors: 0 })).toBe('Backup complete: 1 saved, 0 errors');
  });

  it('names each failed host and why', () => {
    const msg = runBackupPolicyMessage({ backed_up: 0, errors: 2, failures: [failure(1), failure(2)] });
    expect(msg.split('\n')).toEqual([
      'Backup complete: 0 saved, 2 errors',
      '',
      'fw1: reason 1',
      'fw2: reason 2',
    ]);
  });

  it('names a host without a hostname by its address', () => {
    const msg = runBackupPolicyMessage({
      backed_up: 0,
      errors: 1,
      failures: [{ ...failure(7), hostname: '' }],
    });
    expect(msg).toContain('192.0.2.7: reason 7');
  });

  it('points to History for the failures it does not name', () => {
    const failures = [1, 2, 3, 4, 5, 6, 7].map(failure);
    const msg = runBackupPolicyMessage({ backed_up: 0, errors: 9, failures });
    expect(msg).toContain('fw5: reason 5');
    expect(msg).not.toContain('fw6');
    expect(msg).toMatch(/4 more failed: see their error entries under History/);
    // A server that names no failures: every reason is under History.
    expect(runBackupPolicyMessage({ backed_up: 0, errors: 1 })).toMatch(
      /1 failed: see their error entries under History/,
    );
  });
});
