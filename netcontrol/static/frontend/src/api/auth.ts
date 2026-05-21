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
  must_change_password?: boolean;
  idle_timeout_seconds?: number;
  session_last_activity?: number;
  session_never_expires?: boolean;
  server_time?: number;
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
