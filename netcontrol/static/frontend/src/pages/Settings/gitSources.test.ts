import { describe, expect, it } from 'vitest';

import {
  emptyGitSource,
  objectCountText,
  remoteUrlError,
  shortSha,
  statusBadge,
  syncResultText,
  validateGitSource,
} from './gitSources';

describe('remoteUrlError', () => {
  it.each([
    'https://git.example.com/netops/configs.git',
    'ssh://git@git.example.com:2222/netops/configs.git',
    'git@git.example.com:netops/configs.git',
  ])('accepts %s', (url) => {
    expect(remoteUrlError(url)).toBeUndefined();
  });

  it.each([
    ['', 'Enter'],
    ['file:///srv/repo.git', 'not allowed'],
    ['http://git.example.com/r.git', 'not allowed'],
    ['ext::sh -c id', 'spaces'],
    ['ext::sh', 'ext::'],
    ['/srv/repo.git', 'Use https'],
    ['https://svc:pw@git.example.com/r.git', 'credentials'],
    ['https://token@git.example.com/r.git', 'credentials'],
    ['https://git.example.com', 'repository path'],
    ['https://git.example.com/', 'repository path'],
    ['git@git.example.com:-oProxyCommand=x', 'Use https'],
  ])('refuses %s', (url, message) => {
    expect(remoteUrlError(url)).toContain(message);
  });
});

describe('validateGitSource', () => {
  const valid = {
    ...emptyGitSource(['templates', 'playbooks', 'config_contexts']),
    name: 'netops-configs',
    remote_url: 'https://git.example.com/netops/configs.git',
  };

  it('passes a complete source', () => {
    expect(validateGitSource(valid)).toEqual({});
  });

  it('names each bad field', () => {
    const errors = validateGitSource({
      ...valid,
      name: ' ',
      branch: '-x',
      provides: [],
      sync_interval_minutes: 2,
    });
    expect(Object.keys(errors).sort()).toEqual(['branch', 'interval', 'name', 'provides']);
  });

  it('allows on-demand only and the interval bounds', () => {
    for (const n of [0, 5, 10080]) expect(validateGitSource({ ...valid, sync_interval_minutes: n })).toEqual({});
    expect(validateGitSource({ ...valid, sync_interval_minutes: 10081 }).interval).toBeDefined();
  });
});

describe('display helpers', () => {
  it('maps statuses to badges', () => {
    expect(statusBadge('ok')).toEqual({ tone: 'success', label: 'Synced' });
    expect(statusBadge('error').tone).toBe('danger');
    expect(statusBadge('odd')).toEqual({ tone: 'neutral', label: 'odd' });
  });

  it('shortens commits and counts records', () => {
    expect(shortSha('0123456789abcdef')).toBe('0123456789');
    expect(shortSha(null)).toBe('');
    expect(objectCountText({ templates: 2, playbooks: 1, config_contexts: 0 })).toBe('2 templates, 1 playbook');
    expect(objectCountText({})).toBe('');
  });

  it('summarizes a sync', () => {
    const none = { created: 0, updated: 0, unchanged: 0, removed: 0, detached: 0 };
    expect(
      syncResultText({
        commit: '0123456789abcdef',
        counts: {
          templates: { ...none, created: 2 },
          playbooks: { ...none, removed: 1 },
          config_contexts: { ...none, unchanged: 3 },
        },
        warnings: [{ path: 'playbooks/x.py', message: 'Skipped' }],
      }),
    ).toBe('Commit 0123456789: 2 created, 1 removed, 1 file skipped.');
    expect(
      syncResultText({
        commit: 'abc',
        counts: { templates: none, playbooks: none, config_contexts: none },
        warnings: [],
      }),
    ).toBe('Commit abc: no changes.');
  });
});
