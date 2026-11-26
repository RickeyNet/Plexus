import { MutationObserver, QueryCache, QueryClient, QueryObserver } from '@tanstack/react-query';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { authStatusQueryOptions } from './auth';
import { resetSessionExpiryFlag, setCsrfToken, setSessionExpiredHandler } from './client';
import { intendedConfigApi } from './intendedConfig';

// The client main.tsx builds, with a spy where a global error toast would go.
function client(onError = vi.fn()) {
  return new QueryClient({
    queryCache: new QueryCache({ onError }),
    defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: false, staleTime: 30_000 } },
  });
}

// A fetch that never answers on its own and rejects like the browser's once
// its signal aborts; records the init of each call.
function hangingFetch() {
  const inits: (RequestInit | undefined)[] = [];
  const fetchMock = vi.fn((_url: string, init?: RequestInit) => {
    inits.push(init);
    return new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
    });
  });
  vi.stubGlobal('fetch', fetchMock);
  return { fetchMock, inits };
}

const flush = () => new Promise((resolve) => setTimeout(resolve, 20));

afterEach(() => {
  vi.unstubAllGlobals();
  setSessionExpiredHandler(null);
  resetSessionExpiryFlag();
  setCsrfToken(null);
});

describe('query cancellation', () => {
  it('aborts the fetch when the last observer leaves, without an error, retry or sign-out', async () => {
    const { fetchMock, inits } = hangingFetch();
    const onError = vi.fn();
    const expired = vi.fn();
    setSessionExpiredHandler(expired);
    const qc = client(onError);

    const observer = new QueryObserver(qc, authStatusQueryOptions);
    const unsubscribe = observer.subscribe(() => {});
    await flush();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const signal = inits[0]?.signal;
    expect(signal).toBeInstanceOf(AbortSignal);
    expect(signal?.aborted).toBe(false);

    // Navigating away unmounts the page: its observers unsubscribe.
    unsubscribe();
    await flush();

    expect(signal?.aborted).toBe(true);
    const state = qc.getQueryState(authStatusQueryOptions.queryKey);
    expect(state?.error).toBeNull();
    expect(state?.fetchStatus).toBe('idle');
    expect(onError).not.toHaveBeenCalled();
    expect(expired).not.toHaveBeenCalled();
    // retry: 1 does not send the cancelled request again.
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('aborts on cancelQueries and a read helper forwards the signal it is given', async () => {
    const { inits } = hangingFetch();
    const qc = client();
    const observer = new QueryObserver(qc, {
      queryKey: ['intended-config', 'template', 3],
      queryFn: ({ signal }) => intendedConfigApi.template(3, { signal }),
    });
    const unsubscribe = observer.subscribe(() => {});
    await flush();
    await qc.cancelQueries({ queryKey: ['intended-config'] });
    expect(inits[0]?.signal?.aborted).toBe(true);
    expect(observer.getCurrentResult().error).toBeNull();
    unsubscribe();
  });

  it('sends a mutation without a signal', async () => {
    const inits: (RequestInit | undefined)[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_url: string, init?: RequestInit) => {
        inits.push(init);
        return new Response(JSON.stringify({ hosts: 1 }), { headers: { 'content-type': 'application/json' } });
      }),
    );
    const qc = client();
    const mutation = new MutationObserver(qc, { mutationFn: intendedConfigApi.generate });
    await mutation.mutate({});
    expect(inits).toHaveLength(1);
    expect(inits[0]?.signal).toBeUndefined();
  });
});

// Every query in the app forwards TanStack Query's signal; mutations never
// take one. Checked on the source so a new hook cannot forget it.
describe('query functions in the source', () => {
  // Vite inlines every source file as text; the tests run in Vitest only.
  const sources = Object.entries(
    import.meta.glob<string>(['../**/*.{ts,tsx}', '!../**/*.test.{ts,tsx}'], {
      query: '?raw',
      import: 'default',
      eager: true,
    }),
  );

  it('found the source', () => {
    expect(sources.length).toBeGreaterThan(100);
  });

  it('take the signal', () => {
    const missing: string[] = [];
    for (const [file, text] of sources) {
      text.split('\n').forEach((line, i) => {
        if (/\bqueryFn:/.test(line) && !/\bsignal\b/.test(line)) missing.push(`${file}:${i + 1}`);
      });
    }
    expect(missing).toEqual([]);
  });

  it('are never mutations', () => {
    const offending = sources
      .filter(([, text]) => /mutationFn:\s*(async\s*)?\(\s*\{[^}]*\bsignal\b/.test(text))
      .map(([file]) => file);
    expect(offending).toEqual([]);
  });
});

declare global {
  interface ImportMeta {
    glob<T>(
      patterns: string | string[],
      options: { query: string; import: string; eager: true },
    ): Record<string, T>;
  }
}
