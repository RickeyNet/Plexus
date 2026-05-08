/**
 * Thin fetch wrapper around the Plexus FastAPI backend.
 *
 * - Always sends cookies (session auth).
 * - Reads the CSRF token cached after login and attaches `X-CSRF-Token` to
 *   state-changing requests, matching the contract enforced by app.py.
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

// Tripped on the first 401 so concurrent page queries don't each trigger a
// separate reload when the server-side session has idle-expired.
let sessionExpiryHandled = false;

// Set by App at boot — invalidates auth status so the React gate flips to the
// login screen. Falls back to a hard reload if no handler is registered yet.
let onSessionExpired: (() => void) | null = null;
export function setSessionExpiredHandler(fn: (() => void) | null): void {
  onSessionExpired = fn;
}
export function resetSessionExpiryFlag(): void {
  sessionExpiryHandled = false;
}

export interface ApiRequestOptions extends Omit<RequestInit, 'body' | 'headers'> {
  body?: unknown;
  headers?: Record<string, string>;
}

export async function apiRequest<T = unknown>(
  endpoint: string,
  options: ApiRequestOptions = {},
): Promise<T> {
  const { body, headers = {}, method = 'GET', ...rest } = options;

  const finalHeaders: Record<string, string> = {
    Accept: 'application/json',
    ...headers,
  };

  if (csrfToken && MUTATION_METHODS.has(method.toUpperCase())) {
    finalHeaders['X-CSRF-Token'] = csrfToken;
  }

  let serializedBody: BodyInit | undefined;
  if (body !== undefined) {
    if (body instanceof FormData || typeof body === 'string') {
      serializedBody = body;
    } else {
      finalHeaders['Content-Type'] ??= 'application/json';
      serializedBody = JSON.stringify(body);
    }
  }

  const res = await fetch(`${API_BASE}${endpoint}`, {
    ...rest,
    method,
    credentials: 'include',
    headers: finalHeaders,
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

  if (!res.ok) {
    const detail =
      (parsed && typeof parsed === 'object' && 'detail' in parsed
        ? String((parsed as { detail: unknown }).detail)
        : null) ?? res.statusText;
    if (
      res.status === 401 &&
      endpoint !== '/auth/login' &&
      endpoint !== '/auth/status'
    ) {
      if (!sessionExpiryHandled) {
        sessionExpiryHandled = true;
        setCsrfToken(null);
        if (onSessionExpired) onSessionExpired();
        else window.location.assign('/');
      }
    }
    throw new ApiError(res.status, parsed, `${res.status} ${detail}`);
  }

  return parsed as T;
}
