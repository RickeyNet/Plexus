import { QueryClient, QueryObserver } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { authStatusQueryOptions } from '@/api/auth';
import { pageLoaders } from '@/lib/pageLoaders';

import { startEarlyLoads } from './startupPreload';

const mocks = vi.hoisted(() => ({
  apiRequest: vi.fn(),
  setCsrfToken: vi.fn(),
  dashboard: vi.fn(),
  monitoring: vi.fn(),
  deviceDetail: vi.fn(),
}));

vi.mock('@/api/client', () => ({
  apiRequest: mocks.apiRequest,
  setCsrfToken: mocks.setCsrfToken,
}));

// Only the loaders these tests reach; the real ones import whole page chunks.
vi.mock('@/lib/pageLoaders', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/pageLoaders')>();
  Object.assign(actual.pageLoaders, {
    dashboard: mocks.dashboard,
    monitoring: mocks.monitoring,
    deviceDetail: mocks.deviceDetail,
  });
  return actual;
});

function client() {
  return new QueryClient({
    defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: false, staleTime: 30_000 } },
  });
}

describe('startEarlyLoads', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.apiRequest.mockResolvedValue({ authenticated: true, username: 'alice', csrf_token: 'tok' });
    for (const loader of [mocks.dashboard, mocks.monitoring, mocks.deviceDetail]) {
      loader.mockResolvedValue({});
    }
  });

  it('prefetches the auth status once and the hook reads the cached result', async () => {
    const qc = client();
    startEarlyLoads(qc, '/');
    // The hook mounts while the prefetch is still in flight.
    const observer = new QueryObserver(qc, authStatusQueryOptions);
    const unsubscribe = observer.subscribe(() => {});
    await vi.waitFor(() => expect(observer.getCurrentResult().isSuccess).toBe(true));
    unsubscribe();

    // A second mount after the answer arrived does not refetch either.
    const later = new QueryObserver(qc, authStatusQueryOptions);
    const unsubscribeLater = later.subscribe(() => {});
    expect(later.getCurrentResult().data?.username).toBe('alice');
    unsubscribeLater();

    expect(mocks.apiRequest).toHaveBeenCalledTimes(1);
    expect(mocks.apiRequest).toHaveBeenCalledWith('/auth/status', { signal: expect.any(AbortSignal) });
    expect(mocks.setCsrfToken).toHaveBeenCalledWith('tok');
  });

  it('starts the chunk for the current route', () => {
    startEarlyLoads(client(), '/');
    expect(mocks.dashboard).toHaveBeenCalledTimes(1);
  });

  it('resolves deep links to their page chunk', () => {
    startEarlyLoads(client(), '/monitoring/configure/suppressions');
    startEarlyLoads(client(), '/devices/12');
    expect(mocks.monitoring).toHaveBeenCalledTimes(1);
    expect(mocks.deviceDetail).toHaveBeenCalledTimes(1);
  });

  it('loads no page chunk on the login path', () => {
    startEarlyLoads(client(), '/login');
    expect(mocks.dashboard).not.toHaveBeenCalled();
    expect(mocks.monitoring).not.toHaveBeenCalled();
    expect(mocks.deviceDetail).not.toHaveBeenCalled();
  });

  it('attaches a rejection handler to the chunk preload', () => {
    const failed = Promise.reject(new Error('chunk load failed'));
    // catch() goes through then(undefined, onRejected), so watching then sees either form.
    const then = vi.spyOn(failed, 'then');
    // A plain function, not vi.fn: a mock attaches its own then() to track settled results.
    Object.assign(pageLoaders, { dashboard: () => failed });
    try {
      expect(() => startEarlyLoads(client(), '/')).not.toThrow();
      expect(then.mock.calls.some(([, onRejected]) => typeof onRejected === 'function')).toBe(true);
    } finally {
      Object.assign(pageLoaders, { dashboard: mocks.dashboard });
    }
  });

  it('keeps a failed auth prefetch silent', async () => {
    mocks.apiRequest.mockRejectedValue(new Error('offline'));
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    expect(() => startEarlyLoads(qc, '/')).not.toThrow();
    await vi.waitFor(() =>
      expect(qc.getQueryState(authStatusQueryOptions.queryKey)?.status).toBe('error'),
    );
  });
});
