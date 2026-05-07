import { describe, expect, it } from 'vitest';

import type { Deployment } from '@/api/deployments';

import {
  canDelete,
  canExecute,
  canRollback,
  commandCount,
  filterDeployments,
  rollbackStatusColor,
  statusColor,
} from './helpers';

const make = (over: Partial<Deployment>): Deployment =>
  ({ id: 1, status: 'planning', ...over }) as Deployment;

describe('action predicates', () => {
  it('canExecute is true only for planning or failed', () => {
    expect(canExecute('planning')).toBe(true);
    expect(canExecute('failed')).toBe(true);
    expect(canExecute('completed')).toBe(false);
    expect(canExecute('executing')).toBe(false);
  });

  it('canRollback covers terminal-success and verification states', () => {
    expect(canRollback('completed')).toBe(true);
    expect(canRollback('failed')).toBe(true);
    expect(canRollback('verified')).toBe(true);
    expect(canRollback('verification_failed')).toBe(true);
    expect(canRollback('planning')).toBe(false);
    expect(canRollback('executing')).toBe(false);
  });

  it('canDelete excludes in-flight states', () => {
    expect(canDelete('planning')).toBe(true);
    expect(canDelete('completed')).toBe(true);
    expect(canDelete('failed')).toBe(true);
    expect(canDelete('rolled-back')).toBe(true);
    expect(canDelete('executing')).toBe(false);
    expect(canDelete('rolling-back')).toBe(false);
  });
});

describe('status color maps', () => {
  it('statusColor falls back to text-muted for unknown', () => {
    expect(statusColor('completed')).toBe('success');
    expect(statusColor('failed')).toBe('danger');
    expect(statusColor(undefined)).toBe('text-muted');
    expect(statusColor('something-new')).toBe('text-muted');
  });

  it('rollbackStatusColor distinguishes completed/failed/in-progress', () => {
    expect(rollbackStatusColor('completed')).toBe('success');
    expect(rollbackStatusColor('failed')).toBe('danger');
    expect(rollbackStatusColor('in-progress')).toBe('warning');
    expect(rollbackStatusColor(null)).toBe('warning');
  });
});

describe('commandCount', () => {
  it('counts non-blank lines and tolerates null', () => {
    expect(commandCount(null)).toBe(0);
    expect(commandCount('')).toBe(0);
    expect(commandCount('one')).toBe(1);
    expect(commandCount('one\ntwo\n\nthree\n   ')).toBe(3);
  });
});

describe('filterDeployments', () => {
  const items: Deployment[] = [
    make({ id: 1, status: 'planning', name: 'Core ACL update', group_name: 'Core' }),
    make({ id: 2, status: 'completed', name: 'Edge BGP tweak', group_name: 'Edge' }),
    make({ id: 3, status: 'planning', name: 'Lab cleanup', description: 'misc' }),
  ];

  it('returns all when filters are empty', () => {
    expect(filterDeployments(items, { query: '', status: '' })).toHaveLength(3);
  });

  it('filters by status', () => {
    const r = filterDeployments(items, { query: '', status: 'planning' });
    expect(r.map((d) => d.id)).toEqual([1, 3]);
  });

  it('text query searches name, group, and description case-insensitively', () => {
    expect(filterDeployments(items, { query: 'edge', status: '' }).map((d) => d.id)).toEqual([2]);
    expect(filterDeployments(items, { query: 'CORE', status: '' }).map((d) => d.id)).toEqual([1]);
    expect(filterDeployments(items, { query: 'misc', status: '' }).map((d) => d.id)).toEqual([3]);
  });

  it('status and query compose', () => {
    const r = filterDeployments(items, { query: 'lab', status: 'planning' });
    expect(r.map((d) => d.id)).toEqual([3]);
  });
});
