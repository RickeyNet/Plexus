import { Badge } from '@/components/Badge';
import { contractStateInfo, coverageInfo, stageInfo } from '@/lib/lifecycle';

/** Badges the Lifecycle tab and the device page share. */

export function StageBadge({ stage }: { stage: string }) {
  const info = stageInfo(stage);
  return (
    <Badge size="sm" tone={info.tone}>
      {info.label}
    </Badge>
  );
}

export function CoverageBadge({ coverage }: { coverage: string }) {
  const info = coverageInfo(coverage);
  return (
    <Badge size="sm" tone={info.tone}>
      {info.label}
    </Badge>
  );
}

export function ContractStateBadge({ state }: { state: string }) {
  const info = contractStateInfo(state);
  return (
    <Badge size="sm" tone={info.tone}>
      {info.label}
    </Badge>
  );
}
