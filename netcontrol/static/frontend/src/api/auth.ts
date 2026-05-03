import { useQuery } from '@tanstack/react-query';

import { apiRequest, setCsrfToken } from './client';

export interface AuthStatus {
  authenticated: boolean;
  username?: string;
  display_name?: string;
  role?: string;
  csrf_token?: string;
}

export function useAuthStatus() {
  return useQuery({
    queryKey: ['auth', 'status'],
    queryFn: async () => {
      const status = await apiRequest<AuthStatus>('/auth/status');
      // The backend returns a fresh CSRF token alongside the auth status —
      // mirror what the legacy SPA does and cache it for mutations. When
      // logged out the field is absent, so we clear the cache.
      setCsrfToken(status.csrf_token ?? null);
      return status;
    },
  });
}
