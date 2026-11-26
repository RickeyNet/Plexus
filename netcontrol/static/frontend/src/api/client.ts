/**
 * Thin fetch wrapper around the Plexus FastAPI backend.
 *
 * - Always sends cookies (session auth).
 * - Reads the CSRF token cached after login and attaches `X-CSRF-Token` to
 *   state-changing requests, matching the contract enforced by app.py. A
 *   write the server refuses for its token is sent once more with the token
 *   of the current session.
 * - Throws ApiError with status + parsed body on non-2xx responses so
 *   TanStack Query can surface useful error UI.
 */

const API_BASE = '/api';
const MUTATION_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

export function getCsrfToken(): string | null {
  return csrfToken;
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: unknown,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

// Turn a FastAPI error `detail` into a human string. FastAPI request
// validation (422) returns `detail` as an array of {loc, msg, type} objects;
// String()-ing that yields "[object Object],[object Object]". Flatten it to
// "field: message; field: message" so the UI shows something useful.
export function formatErrorDetail(detail: unknown): string | null {
  if (detail == null) return null;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    const msgs = detail
      .map((item) => {
        if (item && typeof item === 'object' && 'msg' in item) {
          const rec = item as { msg?: unknown; loc?: unknown };
          const loc = Array.isArray(rec.loc)
            ? rec.loc.filter((p) => p !== 'body' && p !== 'query' && p !== 'path')
            : [];
          const field = loc.length ? `${loc.join('.')}: ` : '';
          return `${field}${String(rec.msg)}`;
        }
        return typeof item === 'string' ? item : JSON.stringify(item);
      })
      .filter(Boolean);
    return msgs.length ? msgs.join('; ') : null;
  }
  if (typeof detail === 'object') {
    const rec = detail as { msg?: unknown };
    if ('msg' in rec) return String(rec.msg);
    try {
      return JSON.stringify(detail);
    } catch {
      return null;
    }
  }
  return String(detail);
}

// The message of an error body. app.py wraps every /api/ error as
// `{ok: false, error: {code, message}}`; FastAPI's own shape is `{detail}`.
export function errorMessage(body: unknown): string | null {
  if (!body || typeof body !== 'object') return null;
  const rec = body as { error?: unknown; detail?: unknown };
  if (rec.error && typeof rec.error === 'object' && 'message' in rec.error) {
    const message = (rec.error as { message?: unknown }).message;
    if (typeof message === 'string' && message) return message;
  }
  if (typeof rec.error === 'string' && rec.error) return rec.error;
  return 'detail' in rec ? formatErrorDetail(rec.detail) : null;
}

// Tripped on the first 401 so concurrent page queries don't each trigger a
// separate reload when the server-side session has idle-expired.
let sessionExpiryHandled = false;

// In-flight verification promise - when several queries 401 simultaneously
// we only probe /auth/status once and let the rest await the same answer.
let sessionVerifyInFlight: Promise<boolean> | null = null;

// Probe /api/auth/status to confirm the session is actually dead before
// firing the session-expired handler. Returns true if the session is
// genuinely unauthenticated. Per-endpoint 401s (e.g. a feature-gated route
// that returns 401 for reasons other than session expiry) won't trip the
// global handler when this returns false.
async function isSessionExpired(): Promise<boolean> {
  if (sessionVerifyInFlight) return sessionVerifyInFlight;
  sessionVerifyInFlight = (async () => {
    try {
      const res = await fetch(`${API_BASE}/auth/status`, {
        credentials: 'include',
        headers: { Accept: 'application/json' },
      });
      if (!res.ok) return true;
      const body = (await res.json()) as { authenticated?: boolean };
      return !body?.authenticated;
    } catch {
      // Network error - be conservative and don't force-logout the user.
      return false;
    } finally {
      sessionVerifyInFlight = null;
    }
  })();
  return sessionVerifyInFlight;
}

// Set by App at boot - invalidates auth status so the React gate flips to the
// login screen. Falls back to a hard reload if no handler is registered yet.
let onSessionExpired: (() => void) | null = null;
export function setSessionExpiredHandler(fn: (() => void) | null): void {
  onSessionExpired = fn;
}
export function resetSessionExpiryFlag(): void {
  sessionExpiryHandled = false;
}

// A CSRF token belongs to one session. A tab keeps its token while another
// tab signs in again, and the cookie both tabs share then names a session
// the token was not issued to: the server answers 403 `csrf_error` before
// the route runs.
function isCsrfError(status: number, body: unknown): boolean {
  if (status !== 403 || !body || typeof body !== 'object') return false;
  const error = (body as { error?: unknown }).error;
  return !!error && typeof error === 'object' && (error as { code?: unknown }).code === 'csrf_error';
}

// Cache the token of the session the cookie names now. Returns whether the
// server gave one (it gives none to a signed-out browser).
async function refreshCsrfToken(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/auth/status`, {
      credentials: 'include',
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) return false;
    const body = (await res.json()) as { csrf_token?: unknown };
    if (typeof body?.csrf_token !== 'string' || !body.csrf_token) return false;
    setCsrfToken(body.csrf_token);
    return true;
  } catch {
    return false;
  }
}

export interface ApiRequestOptions extends Omit<RequestInit, 'body' | 'headers'> {
  body?: unknown;
  headers?: Record<string, string>;
}

/**
 * Options a read helper passes through to `apiRequest`: a query hands over
 * TanStack Query's `signal` (`queryFn: ({ signal }) => get(x, { signal })`)
 * so leaving the page aborts the fetch. Mutations never take one.
 */
export type ReadOptions = Pick<ApiRequestOptions, 'signal'>;

export async function apiRequest<T = unknown>(
  endpoint: string,
  options: ApiRequestOptions = {},
): Promise<T> {
  const { body, headers = {}, method = 'GET', ...rest } = options;

  const finalHeaders: Record<string, string> = {
    Accept: 'application/json',
    ...headers,
  };

  const isMutation = MUTATION_METHODS.has(method.toUpperCase());

  let serializedBody: BodyInit | undefined;
  if (body !== undefined) {
    if (body instanceof FormData || typeof body === 'string') {
      serializedBody = body;
    } else {
      finalHeaders['Content-Type'] ??= 'application/json';
      serializedBody = JSON.stringify(body);
    }
  }

  // The token is read at send time, so a second send carries a fresh one.
  const send = async (): Promise<{ res: Response; parsed: unknown }> => {
    const res = await fetch(`${API_BASE}${endpoint}`, {
      ...rest,
      method,
      credentials: 'include',
      headers:
        csrfToken && isMutation ? { ...finalHeaders, 'X-CSRF-Token': csrfToken } : finalHeaders,
      body: serializedBody,
    });
    const text = await res.text();
    let parsed: unknown = text;
    if (text && res.headers.get('content-type')?.includes('application/json')) {
      try {
        parsed = JSON.parse(text);
      } catch {
        // Leave as text if the server lied about content-type.
      }
    }
    return { res, parsed };
  };

  let { res, parsed } = await send();
  // A refused token is replaced and the request sent once more: the server
  // refused it before the route ran, so nothing happens twice.
  if (isMutation && isCsrfError(res.status, parsed) && (await refreshCsrfToken())) {
    ({ res, parsed } = await send());
  }

  if (!res.ok) {
    const detail = errorMessage(parsed) ?? res.statusText;
    if (
      res.status === 401 &&
      endpoint !== '/auth/login' &&
      endpoint !== '/auth/status'
    ) {
      // Verify the session is actually dead before forcing the user out.
      // Some endpoints return 401 for reasons orthogonal to session validity
      // (e.g. feature gating that re-checks the user record). Probing
      // /auth/status lets us tell genuine session expiry apart from those
      // and avoids a render-thrash loop when one endpoint is misbehaving.
      if (!sessionExpiryHandled) {
        const expired = await isSessionExpired();
        if (expired && !sessionExpiryHandled) {
          sessionExpiryHandled = true;
          setCsrfToken(null);
          if (onSessionExpired) onSessionExpired();
          else window.location.assign('/');
        }
      }
    }
    throw new ApiError(res.status, parsed, `${res.status} ${detail}`);
  }

  return parsed as T;
}

/**
 * A `?a=1&b=x` query string from `params`, leaving out undefined, null and
 * empty values; '' when nothing is left.
 */
export function queryString(params: object): string {
  const cleaned: Record<string, string> = {};
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue;
    cleaned[k] = String(v);
  }
  const search = new URLSearchParams(cleaned).toString();
  return search ? `?${search}` : '';
}
