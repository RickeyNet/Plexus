import { afterEach, describe, expect, it, vi } from 'vitest';

import { ApiError, apiRequest, errorMessage, formatErrorDetail, getCsrfToken, setCsrfToken } from './client';

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const CSRF_REFUSED = { ok: false, error: { code: 'csrf_error', message: 'Missing or invalid CSRF token' } };

// Answers the calls of one test in order and records what was sent.
function stubFetch(...answers: Response[]) {
  const calls: { url: string; token: string | undefined }[] = [];
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    const headers = (init?.headers ?? {}) as Record<string, string>;
    calls.push({ url, token: headers['X-CSRF-Token'] });
    const answer = answers.shift();
    if (!answer) throw new Error(`unexpected request to ${url}`);
    return answer;
  });
  vi.stubGlobal('fetch', fetchMock);
  return calls;
}

describe('apiRequest and a refused CSRF token', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    setCsrfToken(null);
  });

  it('takes the token of the current session and sends the write once more', async () => {
    setCsrfToken('stale');
    const calls = stubFetch(
      json(403, CSRF_REFUSED),
      json(200, { authenticated: true, csrf_token: 'fresh' }),
      json(200, { ok: true }),
    );

    await expect(apiRequest('/groups', { method: 'POST', body: { name: 'core' } })).resolves.toEqual({ ok: true });

    expect(calls).toEqual([
      { url: '/api/groups', token: 'stale' },
      { url: '/api/auth/status', token: undefined },
      { url: '/api/groups', token: 'fresh' },
    ]);
    expect(getCsrfToken()).toBe('fresh');
  });

  it('gives up after one more refusal', async () => {
    setCsrfToken('stale');
    const calls = stubFetch(
      json(403, CSRF_REFUSED),
      json(200, { authenticated: true, csrf_token: 'fresh' }),
      json(403, CSRF_REFUSED),
    );

    await expect(apiRequest('/groups', { method: 'POST', body: {} })).rejects.toBeInstanceOf(ApiError);
    expect(calls).toHaveLength(3);
  });

  it('does not send again when the browser is signed out', async () => {
    setCsrfToken('stale');
    const calls = stubFetch(json(403, CSRF_REFUSED), json(200, { authenticated: false }));

    await expect(apiRequest('/groups', { method: 'POST', body: {} })).rejects.toMatchObject({ status: 403 });
    expect(calls).toHaveLength(2);
    expect(getCsrfToken()).toBe('stale');
  });

  it('leaves every other 403 alone', async () => {
    setCsrfToken('good');
    const calls = stubFetch(json(403, { ok: false, error: { code: 'http_error', message: 'Admin access required' } }));

    await expect(apiRequest('/groups', { method: 'POST', body: {} })).rejects.toMatchObject({ status: 403 });
    expect(calls).toHaveLength(1);
  });
});

describe('errorMessage', () => {
  it("reads the message of the app's {ok, error} envelope", () => {
    const body = { ok: false, error: { code: 'http_error', message: "Invalid AWS instance ID 'foo'" } };
    expect(errorMessage(body)).toBe("Invalid AWS instance ID 'foo'");
    expect(errorMessage({ ok: false, error: 'git fetch failed' })).toBe('git fetch failed');
  });

  it("falls back to FastAPI's detail, and to nothing", () => {
    expect(errorMessage({ detail: 'Deployment not found' })).toBe('Deployment not found');
    expect(errorMessage({ detail: [{ msg: 'Field required', loc: ['body', 'name'] }] })).toBe('name: Field required');
    expect(errorMessage({ ok: false, error: { code: 'x', message: '' } })).toBeNull();
    expect(errorMessage('plain text')).toBeNull();
    expect(errorMessage(null)).toBeNull();
  });
});

describe('formatErrorDetail', () => {
  it('returns a plain string detail unchanged', () => {
    expect(formatErrorDetail('Deployment not found')).toBe('Deployment not found');
  });

  it('flattens a FastAPI 422 validation array into field: message pairs', () => {
    const detail = [
      { type: 'missing', loc: ['body', 'name'], msg: 'Field required' },
      { type: 'less_than', loc: ['query', 'limit'], msg: 'Input should be >= 1' },
    ];
    // Must NOT be "[object Object],[object Object]".
    expect(formatErrorDetail(detail)).toBe(
      'name: Field required; limit: Input should be >= 1',
    );
  });

  it('handles a single validation object', () => {
    expect(formatErrorDetail({ msg: 'bad value', loc: ['body', 'x'] })).toBe('bad value');
  });

  it('returns null for null/undefined', () => {
    expect(formatErrorDetail(null)).toBeNull();
    expect(formatErrorDetail(undefined)).toBeNull();
  });

  it('drops loc container prefixes but keeps nested field paths', () => {
    const detail = [{ msg: 'too long', loc: ['body', 'image_map', 'key'] }];
    expect(formatErrorDetail(detail)).toBe('image_map.key: too long');
  });
});
