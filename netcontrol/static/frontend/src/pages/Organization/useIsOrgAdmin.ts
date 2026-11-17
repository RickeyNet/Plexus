import { useAuthStatus } from '@/api/auth';

/** Whether the user may change regions, tenant groups and tenants (admins only, like the other catalogues). */
export function useIsOrgAdmin(): boolean {
  return useAuthStatus().data?.role === 'admin';
}
