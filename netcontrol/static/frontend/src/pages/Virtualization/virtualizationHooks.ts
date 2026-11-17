import { useAuthStatus } from '@/api/auth';
import { canWriteFeature } from '@/lib/tabGating';

export { useConfirmDelete } from '@/components/useConfirmDelete';

/** Whether the user may change virtualization records (admin or `virtualization.write`). */
export function useCanWriteVirtualization(): boolean {
  return canWriteFeature('virtualization', useAuthStatus().data);
}
