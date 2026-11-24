import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest, setCsrfToken } from './client';

export interface AuthStatus {
  authenticated: boolean;
  username?: string;
  display_name?: string;
  role?: string;
  csrf_token?: string;
  feature_access?: string[];
  feature_visibility_hidden?: string[];
  /** Sent with a signed-in status: the account's inventory group limits. */
  object_scope?: ObjectScopeStatus;
  must_change_password?: boolean;
  idle_timeout_seconds?: number;
  session_last_activity?: number;
  session_never_expires?: boolean;
  server_time?: number;
  /** Sent with a logged-out status: whether the server accepts /auth/register. */
  allow_self_register?: boolean;
  /** Sent with a logged-out status: single sign-on offered on the login screen. */
  sso?: SsoStatus;
}

/** Object-level permissions: ``restricted`` accounts see only the inventory
 * groups they are granted and may change only ``write_group_ids`` (expanded
 * with sub-groups; empty when unrestricted). */
export interface ObjectScopeStatus {
  restricted: boolean;
  write_group_ids: number[];
  /** A restricted account with no writable grant or scope rule: every
   * feature is read only for it. Missing on older servers. */
  read_only?: boolean;
}

export interface SsoMethodStatus {
  enabled: boolean;
  label: string;
  /** Lead with the SSO button and fold the password form away. */
  primary: boolean;
}

export type SsoProtocol = 'oidc' | 'saml';

export interface SsoStatus {
  oidc?: SsoMethodStatus;
  saml?: SsoMethodStatus;
}

export interface SsoMethod extends SsoMethodStatus {
  protocol: SsoProtocol;
}

/** The single sign-on methods to offer, OIDC first then SAML. */
export function enabledSsoMethods(sso: SsoStatus | undefined): SsoMethod[] {
  const out: SsoMethod[] = [];
  for (const protocol of ['oidc', 'saml'] as const) {
    const method = sso?.[protocol];
    if (method?.enabled) out.push({ ...method, protocol });
  }
  return out;
}

/** Codes the OIDC callback and SAML ACS put in /login?sso_error=, each with a fixed
 * sentence. Nothing the provider sends is ever shown. */
export const SSO_ERROR_MESSAGES: Record<string, string> = {
  disabled: 'Single sign-on is not enabled. Sign in with a local account.',
  setup:
    'Single sign-on is not set up yet: an administrator must save the single sign-on settings once. Sign in with a local account.',
  state: 'The sign-in request expired or did not match. Try again.',
  provider: 'The identity provider could not be reached or returned an error. Try again or contact an administrator.',
  token: 'The identity provider’s response could not be verified. Contact an administrator.',
  claims: 'Your identity provider account is missing information Plexus needs. Contact an administrator.',
  account: 'Your account could not be signed in through single sign-on. Contact an administrator.',
  denied: 'Sign-in was refused. Wait a few minutes and try again, or contact an administrator.',
};

/** The sentence for an sso_error code in a query string, or null. */
export function ssoErrorMessage(search: string): string | null {
  const code = new URLSearchParams(search).get('sso_error');
  if (!code) return null;
  return SSO_ERROR_MESSAGES[code] ?? SSO_ERROR_MESSAGES.provider;
}

/** Where an SSO button navigates: the protocol's login route, carrying the
 * page the user was on (the login screen renders at any path) so they come
 * back to it. /login itself is not worth returning to. */
export function ssoLoginHref(pathname: string, search = '', protocol: SsoProtocol = 'oidc'): string {
  const base = `/api/auth/${protocol}/login`;
  const params = new URLSearchParams(search);
  params.delete('sso_error');
  const rest = params.toString();
  const next = `${pathname}${rest ? `?${rest}` : ''}`;
  if (!pathname.startsWith('/') || pathname === '/' || pathname === '/login') {
    return base;
  }
  return `${base}?next=${encodeURIComponent(next)}`;
}

export interface LoginResponse {
  ok: true;
  username: string;
  user_id: number;
  display_name: string;
  role: string;
  auth_source?: string;
  feature_access: string[];
  feature_visibility_hidden: string[];
  object_scope?: ObjectScopeStatus;
  must_change_password: boolean;
  csrf_token: string;
}

export function useAuthStatus() {
  return useQuery({
    queryKey: ['auth', 'status'],
    queryFn: async () => {
      const status = await apiRequest<AuthStatus>('/auth/status');
      // The backend returns a fresh CSRF token alongside the auth status -
      // mirror what the legacy SPA does and cache it for mutations. When
      // logged out the field is absent, so we clear the cache.
      setCsrfToken(status.csrf_token ?? null);
      return status;
    },
    // The global default disables refetchOnWindowFocus, but auth state is the
    // one place we want it: if a user logs out (or in) in another tab, this
    // tab notices on the next focus instead of waiting for a 401.
    refetchOnWindowFocus: true,
  });
}

/** Whether the signed-in user is an admin. */
export function useIsAdmin(): boolean {
  return useAuthStatus().data?.role === 'admin';
}

export function useLogin() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (vars: { username: string; password: string }) => {
      const res = await apiRequest<LoginResponse>('/auth/login', {
        method: 'POST',
        body: { username: vars.username, password: vars.password },
      });
      setCsrfToken(res.csrf_token);
      return res;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['auth', 'status'] });
    },
  });
}

export function useRegister() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (vars: {
      username: string;
      password: string;
      display_name?: string;
    }) => {
      const res = await apiRequest<LoginResponse>('/auth/register', {
        method: 'POST',
        body: vars,
      });
      setCsrfToken(res.csrf_token);
      return res;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['auth', 'status'] });
    },
  });
}

export function useUpdateProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (vars: { display_name: string }) =>
      apiRequest<{ ok: true }>('/auth/profile', {
        method: 'PUT',
        body: vars,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['auth', 'status'] });
    },
  });
}

export interface HeartbeatResponse {
  ok: true;
  session_last_activity: number;
  idle_timeout_seconds: number;
  server_time: number;
}

export function useSessionHeartbeat() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiRequest<HeartbeatResponse>('/auth/heartbeat', { method: 'POST' }),
    onSuccess: (res) => {
      // Apply the new activity timestamp synchronously so the idle countdown
      // resets the moment the heartbeat returns - waiting for the /auth/status
      // refetch leaves a window where the countdown can hit zero and trigger
      // auto-logout even though the server just renewed the session.
      qc.setQueryData<AuthStatus>(['auth', 'status'], (prev) =>
        prev
          ? {
              ...prev,
              session_last_activity: res.session_last_activity,
              idle_timeout_seconds: res.idle_timeout_seconds,
              server_time: res.server_time,
            }
          : prev,
      );
      qc.invalidateQueries({ queryKey: ['auth', 'status'] });
    },
  });
}

export function useLogout() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiRequest<{ ok: true }>('/auth/logout', { method: 'POST' }),
    onSuccess: () => {
      setCsrfToken(null);
      qc.invalidateQueries({ queryKey: ['auth', 'status'] });
    },
  });
}

export function useChangePassword() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (vars: {
      current_password: string;
      new_password: string;
    }) =>
      apiRequest<{ ok: true }>('/auth/change-password', {
        method: 'POST',
        body: vars,
      }),
    onSuccess: () => {
      // After a forced first-login change, must_change_password flips to
      // false on the server - refresh status so the gate re-evaluates.
      qc.invalidateQueries({ queryKey: ['auth', 'status'] });
    },
  });
}
