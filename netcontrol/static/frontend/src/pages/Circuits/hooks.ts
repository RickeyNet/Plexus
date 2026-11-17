import { useAuthStatus } from '@/api/auth';
import { canWriteFeature } from '@/lib/tabGating';

export { useConfirmDelete } from '@/components/useConfirmDelete';

/** Whether the user may change circuits (admin, or the `circuits.write` feature). */
export function useCanWriteCircuits(): boolean {
  return canWriteFeature('circuits', useAuthStatus().data);
}
