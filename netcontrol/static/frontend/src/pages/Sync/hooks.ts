import { useAuthStatus } from '@/api/auth';
import { canWriteFeature } from '@/lib/tabGating';

export { useConfirmDelete } from '@/components/useConfirmDelete';

/** Whether the user may add, edit and run sync jobs (admin, or `sync.write`). */
export function useCanWriteSync(): boolean {
  return canWriteFeature('sync', useAuthStatus().data);
}

/** Connections bind a service credential: only admins change them. */
export function useIsAdmin(): boolean {
  return useAuthStatus().data?.role === 'admin';
}
