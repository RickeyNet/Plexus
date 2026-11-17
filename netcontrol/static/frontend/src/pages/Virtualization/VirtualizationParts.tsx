import { Badge } from '@/components/Badge';
import { vmStatusLabel, vmStatusTone } from '@/lib/virtualization';

/** Pieces the Virtualization tabs share (hooks: `virtualizationHooks.ts`). */

export function VmStatusBadge({ status }: { status: string }) {
  return (
    <Badge size="sm" tone={vmStatusTone(status)}>
      {vmStatusLabel(status)}
    </Badge>
  );
}
