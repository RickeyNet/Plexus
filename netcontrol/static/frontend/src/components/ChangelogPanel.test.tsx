import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ApiError } from '@/api/client';
import type { ObjectChange, ObjectChangeFilter } from '@/api/objectChanges';

import { ChangeDiff, ChangeEntry, ChangelogPanel } from './ChangelogPanel';

const state = vi.hoisted(() => ({
  result: {} as Record<string, unknown>,
  filters: [] as unknown[],
}));

vi.mock('@/api/objectChanges', () => ({
  useObjectChanges: (filter: unknown) => {
    state.filters.push(filter);
    return state.result;
  },
}));

const query = (over: Record<string, unknown>) => ({
  isError: false,
  isPending: false,
  isFetching: false,
  data: undefined,
  error: null,
  refetch: () => {},
  ...over,
});

const UPDATE: ObjectChange = {
  id: 2,
  object_type: 'host',
  object_id: '5',
  object_label: 'edge-r2',
  action: 'update',
  user: 'alice',
  correlation_id: 'c0ffee12',
  changed_at: '2026-01-02 03:04:05',
  changes: { hostname: { before: 'edge-r1', after: 'edge-r2' } },
  before: { id: 5, hostname: 'edge-r1' },
  after: { id: 5, hostname: 'edge-r2' },
};

const CREATE: ObjectChange = {
  ...UPDATE,
  id: 1,
  action: 'create',
  user: '',
  correlation_id: '',
  changes: {},
  before: null,
  after: { id: 5, hostname: 'edge-r1', ip_address: '192.0.2.10' },
};

describe('ChangeDiff', () => {
  it('shows each changed field with its before and after value', () => {
    const html = renderToStaticMarkup(<ChangeDiff change={UPDATE} />);
    expect(html).toContain('hostname');
    expect(html).toContain('edge-r1');
    expect(html).toContain('edge-r2');
    expect(html).toContain('<th>Before</th>');
  });

  it('shows a created object field by field with empty befores', () => {
    const html = renderToStaticMarkup(<ChangeDiff change={CREATE} />);
    expect(html).toContain('ip_address');
    expect(html).toContain('192.0.2.10');
    expect(html).not.toContain('>id<');
  });

  it('says so when no values were recorded', () => {
    const html = renderToStaticMarkup(<ChangeDiff change={{ ...UPDATE, changes: {} }} />);
    expect(html).toContain('No field values recorded.');
  });
});

describe('ChangeEntry', () => {
  it('names the action, user, time and correlation id', () => {
    const html = renderToStaticMarkup(<ChangeEntry change={UPDATE} showObject />);
    expect(html).toContain('Update');
    expect(html).toContain('by alice');
    expect(html).toContain('c0ffee12');
    expect(html).toContain('Host edge-r2');
  });

  it('falls back to system for a change made outside a request', () => {
    expect(renderToStaticMarkup(<ChangeEntry change={CREATE} />)).toContain('by system');
  });
});

describe('ChangelogPanel', () => {
  beforeEach(() => {
    state.filters = [];
  });

  it('queries the object by id and renders its timeline', () => {
    state.result = query({ data: { changes: [UPDATE, CREATE], total: 2, limit: 20, offset: 0, object_types: ['host'] } });
    const html = renderToStaticMarkup(<ChangelogPanel objectType="host" objectId={5} />);
    expect(state.filters[0]).toEqual({ object_type: 'host', object_id: '5', limit: 20, offset: 0 } satisfies ObjectChangeFilter);
    expect(html).toContain('Changelog');
    expect(html).toContain('Update');
    expect(html).toContain('Create');
    expect(html).not.toContain('Older'); // one page only
  });

  it('pages when there are more changes than fit', () => {
    state.result = query({ data: { changes: [UPDATE], total: 3, limit: 1, offset: 0, object_types: ['host'] } });
    const html = renderToStaticMarkup(<ChangelogPanel objectType="host" objectId={5} pageSize={1} />);
    expect(html).toContain('1-1 of 3');
    expect(html).toContain('Older');
  });

  it('queries by label when the object has no id', () => {
    state.result = query({ data: { changes: [], total: 0, limit: 20, offset: 0, object_types: ['prefix'] } });
    const html = renderToStaticMarkup(<ChangelogPanel objectType="prefix" objectLabel="198.51.100.0/24" />);
    expect(state.filters[0]).toMatchObject({ object_type: 'prefix', object_label: '198.51.100.0/24' });
    expect(html).toContain('No changes recorded for this prefix.');
  });

  it('renders nothing without an id or a label', () => {
    expect(renderToStaticMarkup(<ChangelogPanel objectType="prefix" objectLabel="" />)).toBe('');
    expect(state.filters).toEqual([]);
  });

  it('explains a refusal instead of failing', () => {
    state.result = query({ isError: true, error: new ApiError(403, null, '403 Forbidden') });
    expect(renderToStaticMarkup(<ChangelogPanel objectType="vlan" objectId={1} />)).toContain(
      'You do not have access to these changes.',
    );
    state.result = query({ isError: true, error: new Error('500 boom') });
    expect(renderToStaticMarkup(<ChangelogPanel objectType="vlan" objectId={1} />)).toContain(
      'Failed to load the change log',
    );
  });
});
