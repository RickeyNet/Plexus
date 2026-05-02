import { useQuery } from '@tanstack/react-query';

import { apiRequest } from './client';

export interface AuthStatus {
  authenticated: boolean;
  username?: string;
  display_name?: string;
  role?: string;
}

export function useAuthStatus() {
  return useQuery({
    queryKey: ['auth', 'status'],
    queryFn: () => apiRequest<AuthStatus>('/auth/status'),
  });
}
