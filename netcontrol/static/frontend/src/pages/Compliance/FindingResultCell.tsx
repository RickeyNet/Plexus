import { toneColor } from '@/lib/severity';

import { findingOutcome } from './scanHelpers';

/** The Result cell of a findings table: PASS, FAIL or UNREADABLE in its tone. */
export function FindingResultCell({ passed, unreadable }: { passed: boolean | null; unreadable?: boolean }) {
  const { label, tone } = findingOutcome({ passed, unreadable });
  return <td style={{ color: toneColor(tone), fontWeight: 600, whiteSpace: 'nowrap' }}>{label}</td>;
}
